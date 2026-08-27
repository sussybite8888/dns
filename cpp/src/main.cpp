#include "DnsServer.hpp"
#include <iostream>
#include <csignal>
#include <atomic>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#include <unistd.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <vector>
#include <thread>
#include <chrono>

// When launched from a .app bundle (Finder, launchd, ...) the working
// directory is arbitrary, so relative paths like data/dns-overrides.json and
// web/index.html would not resolve. Detect that case, generate the data
// directory on first launch (default database, static dir, web UI extracted
// from the bundle's Resources), and chdir into it so all relative paths work.
// Returns true when running from an app bundle.
static bool setupBundleEnvironment() {
    uint32_t size = 0;
    _NSGetExecutablePath(nullptr, &size);
    std::vector<char> buf(size);
    if (size == 0 || _NSGetExecutablePath(buf.data(), &size) != 0) {
        return false;
    }

    std::error_code ec;
    std::filesystem::path exePath = std::filesystem::canonical(buf.data(), ec);
    if (ec) {
        exePath = buf.data();
    }
    std::string exeStr = exePath.string();
    size_t appPos = exeStr.find(".app/Contents/MacOS/");
    if (appPos == std::string::npos) {
        return false; // Plain CLI binary: keep current-directory behavior
    }

    const char* home = std::getenv("HOME");
    if (!home || *home == '\0') {
        return true;
    }
    std::filesystem::path baseDir =
        std::filesystem::path(home) / "Library" / "Application Support" / "dns-server";

    std::filesystem::create_directories(baseDir / "data" / "static", ec);
    if (ec) {
        std::cerr << "Warning: could not create data directory " << baseDir
                  << ": " << ec.message() << std::endl;
        return true;
    }
    std::filesystem::create_directories(baseDir / "web", ec);

    // First launch: seed an empty overrides database
    std::filesystem::path dbPath = baseDir / "data" / "dns-overrides.json";
    if (!std::filesystem::exists(dbPath, ec)) {
        std::ofstream db(dbPath);
        db << "{\n  \"dnsWhitelistIps\": [],\n  \"overrides\": []\n}\n";
        std::cout << "Created default database: " << dbPath.string() << std::endl;
    }

    // Extract the web UI shipped in the bundle's Resources; update_existing
    // keeps it current after the app is updated without re-copying each run.
    std::filesystem::path resourcesWeb =
        std::filesystem::path(exeStr.substr(0, appPos + 4)) / "Contents" / "Resources" / "web";
    if (std::filesystem::exists(resourcesWeb, ec)) {
        std::filesystem::copy(resourcesWeb, baseDir / "web",
                              std::filesystem::copy_options::recursive |
                              std::filesystem::copy_options::update_existing, ec);
        if (ec) {
            std::cerr << "Warning: could not extract web UI: " << ec.message() << std::endl;
        }
    }

    if (chdir(baseDir.c_str()) != 0) {
        std::cerr << "Warning: could not change to data directory " << baseDir << std::endl;
        return true;
    }
    std::cout << "Running from app bundle; data directory: " << baseDir.string() << std::endl;
    return true;
}

// Open the web UI in the default browser shortly after launch, once the HTTP
// server has had a moment to come up.
static void openWebUiInBrowser(uint16_t httpPort) {
    std::thread([httpPort]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(800));
        std::string command = "open 'http://127.0.0.1:" + std::to_string(httpPort) + "/'";
        if (std::system(command.c_str()) != 0) {
            std::cerr << "Warning: could not open web UI in browser" << std::endl;
        }
    }).detach();
}
#endif

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

#ifdef __APPLE__
    bool launchedFromBundle = setupBundleEnvironment();
#endif

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
        } else if (arg == "--doh-port" && i + 1 < argc) {
            config.dohPort = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--doh-cert" && i + 1 < argc) {
            config.dohCertPath = argv[++i];
        } else if (arg == "--doh-key" && i + 1 < argc) {
            config.dohKeyPath = argv[++i];
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: " << argv[0] << " [options]\n"
                      << "Options:\n"
                      << "  --http-port PORT    HTTP control server port (default: 4167)\n"
                      << "  --dns-port PORT     DNS server port (default: 53)\n"
                      << "  --upstream IP       Upstream DNS server (default: 8.8.8.8)\n"
                      << "  --database PATH     Path to DNS overrides JSON file (default: data/dns-overrides.json)\n"
                      << "  --doh-port PORT     DNS-over-HTTPS (TLS) server port (default: 443)\n"
                      << "  --doh-cert PATH     TLS certificate (PEM) for the native DoH server\n"
                      << "  --doh-key PATH      TLS private key (PEM) for the native DoH server\n"
                      << "  --help, -h         Show this help message\n"
                      << "\n"
                      << "DNS-over-HTTPS (RFC 8484) is always served at /dns-query on the HTTP\n"
                      << "control server (plus a JSON API at /resolve). Provide --doh-cert and\n"
                      << "--doh-key to also run a native HTTPS DoH server on --doh-port.\n";
            return 0;
        }
    }
    
    try {
        DnsServer dnsServer(config);
        g_dnsServer = &dnsServer;

        std::cout << "DNS Server starting..." << std::endl;
        std::cout << "Press Ctrl+C to stop" << std::endl;

#ifdef __APPLE__
        if (launchedFromBundle) {
            openWebUiInBrowser(httpPort);
        }
#endif

        dnsServer.start(httpPort);
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}

