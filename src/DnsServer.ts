import * as dgram from 'dgram';
import * as dns from 'dns';
import * as fs from 'fs';
import * as path from 'path';
import * as http from 'http';
import { encode, decode, Packet, Answer } from 'dns-packet';
import { DnsServerConfig, DnsDatabase, DomainOverride, DnsRecord, DnsQuery } from './types';

export class DnsServer {
  private server: dgram.Socket;
  private httpServer!: http.Server;
  private config: DnsServerConfig;
  private database: DnsDatabase;
  private overridesEnabled: boolean = true;

  constructor(config: DnsServerConfig) {
    this.config = config;
    this.database = this.loadDatabase();
    this.server = dgram.createSocket('udp4');
    this.setupServer();
    this.setupHttpServer();
  }

  private loadDatabase(): DnsDatabase {
    try {
      const data = fs.readFileSync(this.config.databasePath, 'utf8');
      return JSON.parse(data);
    } catch (error) {
      console.warn(`Could not load database from ${this.config.databasePath}, using empty database`);
      return { overrides: [] };
    }
  }

  private setupServer(): void {
    this.server.on('message', (msg, rinfo) => {
      this.handleDnsQuery(msg, rinfo);
    });

    this.server.on('error', (err) => {
      console.error('DNS Server error:', err);
    });

    this.server.on('listening', () => {
      const address = this.server.address();
      console.log(`DNS Server listening on ${address.address}:${address.port}`);
    });
  }

  private async handleDnsQuery(msg: Buffer, rinfo: dgram.RemoteInfo): Promise<void> {
    try {
      const query = decode(msg) as any;
      const domain = query.questions?.[0]?.name;
      const type = query.questions?.[0]?.type;

      if (!domain || !type) {
        this.sendErrorResponse(msg, rinfo, 1); // Format error
        return;
      }

      console.log(`DNS Query: ${domain} (type: ${type})`);

      // Check for domain override (only if overrides are enabled)
      if (this.overridesEnabled) {
        const override = this.findDomainOverride(domain);
        if (override) {
          console.log(`Using override for domain: ${domain}`);
          this.sendOverrideResponse(query, override, rinfo);
          return;
        }
      }

      // Proxy to Google DNS
      console.log(`Proxying to Google DNS: ${domain}`);
      await this.proxyToGoogleDns(query, rinfo);

    } catch (error) {
      console.error('Error handling DNS query:', error);
      this.sendErrorResponse(msg, rinfo, 2); // Server failure
    }
  }

  private findDomainOverride(domain: string): DomainOverride | null {
    return this.database.overrides.find(override => {
      // Check for exact match or wildcard
      if (override.domain === domain) return true;
      if (override.domain.startsWith('*.')) {
        const wildcardDomain = override.domain.substring(2);
        return domain.endsWith(wildcardDomain);
      }
      return false;
    }) || null;
  }

  private sendOverrideResponse(query: any, override: DomainOverride, rinfo: dgram.RemoteInfo): void {
    const answers = override.records.map(record => ({
      name: record.name,
      type: record.type.toUpperCase(), // Use string type instead of number
      class: 'IN' as const,
      ttl: record.ttl || 300,
      data: record.data
    })) as any[];

    const response = {
      id: query.id,
      type: 'response' as const,
      flags: 0x8180, // Response, recursion available
      questions: query.questions,
      answers: answers
    } as any;

    const responseBuffer = encode(response);
    this.server.send(responseBuffer, rinfo.port, rinfo.address);
  }

  private async proxyToGoogleDns(query: any, rinfo: dgram.RemoteInfo): Promise<void> {
    return new Promise((resolve, reject) => {
      const client = dgram.createSocket('udp4');
      const queryBuffer = encode(query);

      client.on('message', (msg) => {
        // Forward the response back to the original client
        this.server.send(msg, rinfo.port, rinfo.address);
        client.close();
        resolve();
      });

      client.on('error', (err) => {
        console.error('Error proxying to Google DNS:', err);
        this.sendErrorResponse(queryBuffer, rinfo, 2); // Server failure
        client.close();
        reject(err);
      });

      // Send query to Google DNS (8.8.8.8)
      client.send(queryBuffer, 53, this.config.upstreamDns, (err) => {
        if (err) {
          console.error('Error sending to Google DNS:', err);
          this.sendErrorResponse(queryBuffer, rinfo, 2);
          client.close();
          reject(err);
        }
      });
    });
  }

  private sendErrorResponse(query: Buffer, rinfo: dgram.RemoteInfo, rcode: number): void {
    try {
      const decodedQuery = decode(query) as any;
      const response = {
        id: decodedQuery.id,
        type: 'response' as const,
        flags: 0x8180 | rcode, // Response flag + error code
        questions: decodedQuery.questions || [],
        answers: []
      } as any;

      const responseBuffer = encode(response);
      this.server.send(responseBuffer, rinfo.port, rinfo.address);
    } catch (error) {
      console.error('Error sending error response:', error);
    }
  }

  private setupHttpServer(): void {
    this.httpServer = http.createServer((req, res) => {
      // Set CORS headers
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

      if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
      }

      if (req.method === 'GET') {
        const url = req.url || '';
        
        if (url === '/enable-overrides') {
          this.overridesEnabled = true;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ 
            status: 'success', 
            message: 'Overrides enabled',
            overridesEnabled: true 
          }));
          console.log('Overrides enabled via HTTP endpoint');
          return;
        }
        
        if (url === '/disable-overrides') {
          this.overridesEnabled = false;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ 
            status: 'success', 
            message: 'Overrides disabled',
            overridesEnabled: false 
          }));
          console.log('Overrides disabled via HTTP endpoint');
          return;
        }
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            message: 'disable: /disable-overrides, enable: /enable-overrides',
          }));
          return;
        }
      }

      // 404 for unknown routes
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'error', message: 'Not found' }));
    });

    this.httpServer.on('error', (err) => {
      console.error('HTTP Server error:', err);
    });

    this.httpServer.on('listening', () => {
      const address = this.httpServer.address();
      if (address && typeof address === 'object') {
        console.log(`HTTP Server listening on ${address.address}:${address.port}`);
      }
    });
  }


  public start(httpPort?: number): void {
    this.server.bind(this.config.port);
    const port = httpPort || 4167;
    this.httpServer.listen(port, '0.0.0.0');
  }

  public stop(): void {
    this.server.close();
    this.httpServer.close();
  }

  public reloadDatabase(): void {
    this.database = this.loadDatabase();
    console.log('Database reloaded');
  }
}
