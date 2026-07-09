# DNS Server with Domain Overrides (C++)

A C++ DNS server that proxies Google DNS by default but can override specific domains using a JSON database.

## Features

- **DNS Proxy**: Forwards queries to Google DNS (8.8.8.8) by default
- **Domain Overrides**: Override specific domains with custom DNS records
- **Wildcard Support**: Support for wildcard domains (e.g., `*.dev.local`)
- **Multiple Record Types**: Support for A, AAAA, CNAME, MX, TXT, NS, SOA, PTR records
- **DNS Control API**: Enable/disable overrides via DNS queries (`enable.control.dns.local` / `disable.control.dns.local`)
- **HTTP Control API**: Enable/disable overrides via HTTP endpoints
- **Modern C++**: C++17 implementation with clean architecture

## Requirements

- C++17 compatible compiler (GCC 7+, Clang 5+, MSVC 2017+)
- CMake 3.15 or higher
- POSIX-compatible system (Linux, macOS, BSD)

## Building

### Using CMake

```bash
mkdir build
cd build
cmake ..
make
```

The executable will be created as `dns-server` in the build directory.

### Installation

```bash
sudo make install
```

This installs the `dns-server` binary to `/usr/local/bin` (or your CMake install prefix).

## Usage

### Running the Server

The server requires root privileges to bind to port 53:

```bash
sudo ./dns-server
```

Or with custom options:

```bash
sudo ./dns-server --dns-port 53 --http-port 4167 --upstream 8.8.8.8 --database data/dns-overrides.json
```

### Command Line Options

- `--http-port PORT`: HTTP control server port (default: 4167)
- `--dns-port PORT`: DNS server port (default: 53)
- `--upstream IP`: Upstream DNS server IP address (default: 8.8.8.8)
- `--database PATH`: Path to DNS overrides JSON file (default: data/dns-overrides.json)
- `--help, -h`: Show help message

### Configuration

The server configuration can be set via command line arguments or by modifying the default values in `main.cpp`.

### Domain Overrides

Domain overrides are defined in the JSON database file (`data/dns-overrides.json`):

```json
{
  "overrides": [
    {
      "domain": "example.local",
      "records": [
        {
          "type": "A",
          "name": "example.local",
          "data": "127.0.0.1",
          "ttl": 300
        }
      ]
    },
    {
      "domain": "*.dev.local",
      "records": [
        {
          "type": "A",
          "name": "*.dev.local",
          "data": "127.0.0.1",
          "ttl": 300
        }
      ]
    }
  ]
}
```

#### Supported Record Types

- **A**: IPv4 address (e.g., "192.168.1.1")
- **AAAA**: IPv6 address (e.g., "::1")
- **CNAME**: Canonical name (e.g., "www.example.com")
- **MX**: Mail exchange (e.g., "10 mail.example.com")
- **TXT**: Text record (e.g., "v=spf1 include:_spf.google.com ~all")
- **NS**: Name server (e.g., "ns1.example.com")
- **SOA**: Start of authority
- **PTR**: Pointer record (for reverse DNS)

#### Wildcard Domains

Use `*.domain.com` to match any subdomain. For example:
- `*.dev.local` matches `api.dev.local`, `test.dev.local`, etc.

### DNS Control API

The server can be controlled via DNS queries to special control domains:

#### Enable Overrides

Resolve `enable.control.dns.local` to enable overrides:

```bash
dig @127.0.0.1 enable.control.dns.local
# or
nslookup enable.control.dns.local 127.0.0.1
```

The server will respond with `127.0.0.1` and enable overrides.

#### Disable Overrides

Resolve `disable.control.dns.local` to disable overrides:

```bash
dig @127.0.0.1 disable.control.dns.local
# or
nslookup disable.control.dns.local 127.0.0.1
```

The server will respond with `127.0.0.2` and disable overrides.

**Note:** Control domains are checked before regular domain overrides, so they work even when overrides are disabled.

### HTTP Control API

The server also provides HTTP endpoints to control override behavior:

#### Enable Overrides

```bash
curl http://localhost:4167/enable-overrides
```

Response:
```json
{
  "status": "success",
  "message": "Overrides enabled",
  "overridesEnabled": true
}
```

#### Disable Overrides

```bash
curl http://localhost:4167/disable-overrides
```

Response:
```json
{
  "status": "success",
  "message": "Overrides disabled",
  "overridesEnabled": false
}
```

#### Status

```bash
curl http://localhost:4167/
```

### Testing the Server

You can test the DNS server using various tools:

#### Using dig (Linux/macOS)

```bash
# Test a regular domain (should proxy to Google DNS)
dig @127.0.0.1 google.com

# Test an overridden domain
dig @127.0.0.1 example.local
```

#### Using nslookup

```bash
# Test a regular domain
nslookup google.com 127.0.0.1

# Test an overridden domain
nslookup example.local 127.0.0.1
```

## Project Structure

```
cpp/
└── src/
    ├── main.cpp          # Main entry point
    ├── DnsServer.hpp     # DNS server class header
    ├── DnsServer.cpp     # DNS server implementation
    ├── DnsPacket.hpp     # DNS packet encoding/decoding header
    ├── DnsPacket.cpp     # DNS packet implementation
    └── types.hpp         # Type definitions

data/
└── dns-overrides.json    # Domain override database

CMakeLists.txt            # CMake build configuration
```

## Dependencies

The project uses CMake's `FetchContent` to automatically download:

- **nlohmann/json** (v3.11.2): JSON parsing library
- **cpp-httplib** (v0.14.3): HTTP server library

These are header-only libraries and are automatically downloaded during the CMake configuration step.

## Differences from TypeScript Version

1. **Manual DNS Packet Handling**: The C++ version implements DNS packet encoding/decoding manually, while the TypeScript version uses the `dns-packet` library.

2. **Socket API**: Uses POSIX sockets directly instead of Node.js's `dgram` module.

3. **JSON Parsing**: Uses `nlohmann/json` instead of Node.js's built-in JSON parser.

4. **HTTP Server**: Uses `cpp-httplib` instead of Node.js's `http` module.

5. **Threading**: Uses `std::thread` for the HTTP server instead of Node.js's event loop.

## Security Considerations

- The server runs on port 53 by default, which requires root privileges on most systems
- Consider running behind a firewall or in a controlled environment
- Validate and sanitize domain override data to prevent injection attacks
- Monitor DNS query logs for suspicious activity
- The HTTP control API has no authentication - consider adding authentication for production use

## Troubleshooting

### Permission Denied

If you get a "Permission denied" error when binding to port 53, make sure to run with `sudo`:

```bash
sudo ./dns-server
```

### Port Already in Use

If port 53 is already in use, you can use a different port:

```bash
sudo ./dns-server --dns-port 5353
```

Note that you'll need to configure your DNS client to use the custom port.

### Build Errors

If you encounter build errors:

1. Ensure you have a C++17 compatible compiler
2. Check that CMake version is 3.15 or higher
3. Ensure you have internet access for downloading dependencies

## License

MIT

