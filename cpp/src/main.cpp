#include "DnsServer.hpp"
#include <iostream>
#include <csignal>
#include <atomic>

std::atomic<bool> g_running(true);
DnsServer* g_dnsServer = nullptr;

void signalHandler(int signal) {
    std::cout << "\nShutting down DNS server..." << std::endl;
    if (g_dnsServer) {
        g_dnsServer->stop();
    }
    g_running = false;
    exit(0);
}

int main(int argc, char* argv[]) {
    // Setup signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    DnsServerConfig config;
    config.port = 53;
    config.upstreamDns = "8.8.8.8";
    config.databasePath = "data/dns-overrides.json";
    
    // Set admin password from build-time define
    #ifdef ADMIN_PASSWORD
    config.adminPassword = std::string(ADMIN_PASSWORD);
    #endif

    // Set DNS whitelist mode from build-time define
    #ifdef ENABLE_DNS_WHITELIST
    config.dnsWhitelistEnabled = (ENABLE_DNS_WHITELIST != 0);
    #endif
    
    // Parse command line arguments
    uint16_t httpPort = 4167;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--http-port" && i + 1 < argc) {
            httpPort = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--dns-port" && i + 1 < argc) {
            config.port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--upstream" && i + 1 < argc) {
            config.upstreamDns = argv[++i];
        } else if (arg == "--database" && i + 1 < argc) {
            config.databasePath = argv[++i];
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: " << argv[0] << " [options]\n"
                      << "Options:\n"
                      << "  --http-port PORT    HTTP control server port (default: 4167)\n"
                      << "  --dns-port PORT     DNS server port (default: 53)\n"
                      << "  --upstream IP       Upstream DNS server (default: 8.8.8.8)\n"
                      << "  --database PATH     Path to DNS overrides JSON file (default: data/dns-overrides.json)\n"
                      << "  --help, -h         Show this help message\n";
            return 0;
        }
    }
    
    try {
        DnsServer dnsServer(config);
        g_dnsServer = &dnsServer;
        
        std::cout << "DNS Server starting..." << std::endl;
        std::cout << "Press Ctrl+C to stop" << std::endl;
        
        dnsServer.start(httpPort);
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}

