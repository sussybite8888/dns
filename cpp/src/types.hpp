#pragma once

#include <string>
#include <vector>
#include <cstdint>

struct DnsRecord {
    std::string type;
    std::string name;
    std::string data;
    uint32_t ttl = 300;
};

struct DomainOverride {
    std::string domain;
    std::vector<DnsRecord> records;
    uint16_t staticPort = 0;  // 0 means no static server
    std::string staticHtmlPath;  // Path to HTML file to serve
};

struct DnsDatabase {
    std::vector<DomainOverride> overrides;
    std::vector<std::string> dnsWhitelistIps;
};

struct DnsServerConfig {
    uint16_t port = 53;
    std::string upstreamDns = "8.8.8.8";
    std::string databasePath = "data/dns-overrides.json";
    std::string adminPassword;  // Password for the web editor
    bool dnsWhitelistEnabled = false;  // Restrict DNS clients by IP when enabled
};

struct DnsQuery {
    uint16_t id;
    std::string type;
    std::string name;
    uint16_t class_;
};

