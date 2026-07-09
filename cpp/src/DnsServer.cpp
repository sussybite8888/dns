#include "DnsServer.hpp"
#include "DnsPacket.hpp"
#include <fstream>
#include <iostream>
#include <cstring>
#include <cerrno>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <nlohmann/json.hpp>
#include <httplib.h>
#include <thread>
#include <stdexcept>
#include <algorithm>
#include <sstream>
#include <cstdlib>
#include <filesystem>
#include <chrono>
#include <ctime>
#include <iomanip>

using json = nlohmann::json;

namespace {
constexpr size_t MAX_BLOCKED_WHITELIST_ATTEMPTS = 20;

bool isValidIpv4Address(const std::string& ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) == 1;
}

std::string extractDnsDomain(const std::vector<uint8_t>& msg) {
    try {
        DnsMessage query = DnsPacket::decode(msg);
        if (!query.questions.empty()) {
            return query.questions[0].name;
        }
    } catch (...) {
        // Ignore decode failures for malformed packets.
    }
    return "unknown";
}
}

DnsServer::DnsServer(const DnsServerConfig& config) 
    : config_(config), overridesEnabled_(true), udpSocket_(-1), tcpSocket_(-1), running_(false) {
    loadDatabase();
}

DnsServer::~DnsServer() {
    stop();
}

void DnsServer::loadDatabase() {
    try {
        std::ifstream file(config_.databasePath);
        if (!file.is_open()) {
            std::cerr << "Warning: Could not load database from " << config_.databasePath 
                      << ", using empty database" << std::endl;
            database_.overrides.clear();
            return;
        }
        
        json j;
        file >> j;
        
        database_.overrides.clear();
        std::vector<std::string> whitelistIps;
        if (j.contains("overrides") && j["overrides"].is_array()) {
            for (const auto& overrideJson : j["overrides"]) {
                DomainOverride override;
                override.domain = overrideJson["domain"].get<std::string>();
                
                if (overrideJson.contains("records") && overrideJson["records"].is_array()) {
                    for (const auto& recordJson : overrideJson["records"]) {
                        DnsRecord record;
                        record.type = recordJson["type"].get<std::string>();
                        record.name = recordJson["name"].get<std::string>();
                        record.data = recordJson["data"].get<std::string>();
                        if (recordJson.contains("ttl")) {
                            record.ttl = recordJson["ttl"].get<uint32_t>();
                        }
                        override.records.push_back(record);
                    }
                }
                if (overrideJson.contains("staticPort")) {
                    override.staticPort = overrideJson["staticPort"].get<uint16_t>();
                }
                if (overrideJson.contains("staticHtmlPath")) {
                    override.staticHtmlPath = overrideJson["staticHtmlPath"].get<std::string>();
                }
                database_.overrides.push_back(override);
            }
        }

        if (j.contains("dnsWhitelistIps") && j["dnsWhitelistIps"].is_array()) {
            for (const auto& ipJson : j["dnsWhitelistIps"]) {
                if (ipJson.is_string()) {
                    std::string ip = ipJson.get<std::string>();
                    if (!ip.empty()) {
                        whitelistIps.push_back(ip);
                    }
                }
            }
        }

        {
            std::lock_guard<std::mutex> lock(dnsWhitelistMutex_);
            database_.dnsWhitelistIps = whitelistIps;
            dnsWhitelistIps_.clear();
            for (const auto& ip : database_.dnsWhitelistIps) {
                dnsWhitelistIps_.insert(ip);
            }
        }
        
        std::cout << "Loaded " << database_.overrides.size() << " domain overrides" << std::endl;
        if (config_.dnsWhitelistEnabled) {
            std::cout << "DNS whitelist enabled with " << dnsWhitelistIps_.size() << " allowed IP(s) from database"
                      << std::endl;
            if (dnsWhitelistIps_.empty()) {
                std::cout << "Warning: DNS whitelist enabled but dnsWhitelistIps is empty; all DNS clients are blocked."
                          << std::endl;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error loading database: " << e.what() << std::endl;
        database_.overrides.clear();
        {
            std::lock_guard<std::mutex> lock(dnsWhitelistMutex_);
            database_.dnsWhitelistIps.clear();
            dnsWhitelistIps_.clear();
        }
    }
}

void DnsServer::setupUdpServer() {
    udpSocket_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket_ < 0) {
        throw std::runtime_error("Failed to create UDP socket");
    }
    
    int opt = 1;
    if (setsockopt(udpSocket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(udpSocket_);
        throw std::runtime_error("Failed to set socket options");
    }
    
    struct sockaddr_in serverAddr;
    std::memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(config_.port);
    
    if (bind(udpSocket_, reinterpret_cast<struct sockaddr*>(&serverAddr), sizeof(serverAddr)) < 0) {
        close(udpSocket_);
        throw std::runtime_error("Failed to bind UDP socket");
    }
    
    std::cout << "DNS Server (UDP) listening on 0.0.0.0:" << config_.port << std::endl;
}

void DnsServer::logBlockedWhitelistAttempt(const std::string& protocol, const std::string& clientAddr,
                                           const std::string& domain) {
    auto now = std::chrono::system_clock::now();
    std::time_t nowTime = std::chrono::system_clock::to_time_t(now);
    std::tm localTm{};
#if defined(_WIN32)
    localtime_s(&localTm, &nowTime);
#else
    localtime_r(&nowTime, &localTm);
#endif
    std::ostringstream ts;
    ts << std::put_time(&localTm, "%Y-%m-%d %H:%M:%S");

    json entry = {
        {"timestamp", ts.str()},
        {"protocol", protocol},
        {"ip", clientAddr},
        {"domain", domain}
    };

    std::lock_guard<std::mutex> lock(blockedAttemptsMutex_);
    blockedWhitelistAttempts_.push_back(entry.dump());
    if (blockedWhitelistAttempts_.size() > MAX_BLOCKED_WHITELIST_ATTEMPTS) {
        blockedWhitelistAttempts_.pop_front();
    }
}

void DnsServer::setupTcpServer() {
    tcpSocket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (tcpSocket_ < 0) {
        throw std::runtime_error("Failed to create TCP socket");
    }
    
    int opt = 1;
    if (setsockopt(tcpSocket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(tcpSocket_);
        throw std::runtime_error("Failed to set TCP socket options");
    }
    
    struct sockaddr_in serverAddr;
    std::memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(config_.port);
    
    if (bind(tcpSocket_, reinterpret_cast<struct sockaddr*>(&serverAddr), sizeof(serverAddr)) < 0) {
        close(tcpSocket_);
        throw std::runtime_error("Failed to bind TCP socket");
    }
    
    if (listen(tcpSocket_, 10) < 0) {
        close(tcpSocket_);
        throw std::runtime_error("Failed to listen on TCP socket");
    }
    
    std::cout << "DNS Server (TCP) listening on 0.0.0.0:" << config_.port << std::endl;
}

void DnsServer::handleTcpConnection(int clientSocket) {
    try {
        // Read the 2-byte length prefix
        uint8_t lengthBytes[2];
        ssize_t received = recv(clientSocket, lengthBytes, 2, MSG_WAITALL);
        if (received != 2) {
            close(clientSocket);
            return;
        }
        
        uint16_t messageLength = (lengthBytes[0] << 8) | lengthBytes[1];
        // DNS spec: max 65535 bytes for TCP messages, but we limit to 4096 for safety
        const uint16_t MAX_DNS_MESSAGE_SIZE = 4096;
        if (messageLength == 0 || messageLength > MAX_DNS_MESSAGE_SIZE) {
            std::cerr << "Invalid DNS message length: " << messageLength << std::endl;
            close(clientSocket);
            return;
        }
        
        // Read the DNS message
        std::vector<uint8_t> buffer(messageLength);
        received = recv(clientSocket, buffer.data(), messageLength, MSG_WAITALL);
        if (received != static_cast<ssize_t>(messageLength)) {
            close(clientSocket);
            return;
        }
        
        // Get client address for logging
        struct sockaddr_in clientAddr;
        socklen_t addrLen = sizeof(clientAddr);
        getpeername(clientSocket, reinterpret_cast<struct sockaddr*>(&clientAddr), &addrLen);
        char clientIp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIp, INET_ADDRSTRLEN);
        uint16_t clientPort = ntohs(clientAddr.sin_port);

        if (!isDnsClientAllowed(std::string(clientIp))) {
            std::string domain = extractDnsDomain(buffer);
            std::cout << "Blocked TCP DNS client (not in whitelist): " << clientIp << std::endl;
            logBlockedWhitelistAttempt("TCP", std::string(clientIp), domain);
            close(clientSocket);
            return;
        }
        
        // Handle the DNS query (same as UDP, but pass TCP socket)
        handleDnsQuery(buffer, std::string(clientIp), clientPort, clientSocket);
        
    } catch (const std::exception& e) {
        std::cerr << "Error handling TCP connection: " << e.what() << std::endl;
    }
    
    close(clientSocket);
}

void DnsServer::sendTcpResponse(int clientSocket, const std::vector<uint8_t>& response) {
    // TCP DNS messages are prefixed with a 2-byte length field
    uint16_t length = htons(static_cast<uint16_t>(response.size()));
    uint8_t lengthBytes[2];
    lengthBytes[0] = (length >> 8) & 0xFF;
    lengthBytes[1] = length & 0xFF;
    
    // Send length prefix
    if (send(clientSocket, lengthBytes, 2, 0) != 2) {
        return;
    }
    
    // Send response
    send(clientSocket, response.data(), response.size(), 0);
}

void DnsServer::sendUdpResponse(const std::vector<uint8_t>& response, const std::string& addr, uint16_t port) {
    struct sockaddr_in clientAddr;
    std::memset(&clientAddr, 0, sizeof(clientAddr));
    clientAddr.sin_family = AF_INET;
    clientAddr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, addr.c_str(), &clientAddr.sin_addr) <= 0) {
        std::cerr << "Invalid client address: " << addr << std::endl;
        return;
    }
    
    sendto(udpSocket_, response.data(), response.size(), 0,
           reinterpret_cast<struct sockaddr*>(&clientAddr), sizeof(clientAddr));
}

std::vector<uint8_t> DnsServer::ensureUdpSize(const DnsMessage& message, int tcpSocket) {
    // If TCP, no size limit
    if (tcpSocket >= 0) {
        return DnsPacket::encode(message);
    }
    
    // For UDP, ensure response fits in 512 bytes
    const size_t MAX_UDP_SIZE = 512;
    DnsMessage trimmedMessage = message;
    // Ensure TC flag and other invalid bits are cleared
    trimmedMessage.clearTruncated();
    // Make sure flags are valid: only QR (0x8000) and RA (0x0080) should be set for normal responses
    // Preserve only the valid response flags
    trimmedMessage.flags = (trimmedMessage.flags & 0x8080) | 0x8000; // QR + RA only
    
    std::vector<uint8_t> encoded = DnsPacket::encode(trimmedMessage);
    
    // If it fits, return as-is
    if (encoded.size() <= MAX_UDP_SIZE) {
        return encoded;
    }
    
    // Otherwise, reduce answers until it fits
    while (encoded.size() > MAX_UDP_SIZE && !trimmedMessage.answers.empty()) {
        trimmedMessage.answers.pop_back();
        trimmedMessage.flags = (trimmedMessage.flags & 0x8080) | 0x8000; // Keep flags clean
        encoded = DnsPacket::encode(trimmedMessage);
    }
    
    // If still too large, remove authority and additional sections
    if (encoded.size() > MAX_UDP_SIZE) {
        trimmedMessage.authority.clear();
        trimmedMessage.additional.clear();
        trimmedMessage.flags = (trimmedMessage.flags & 0x8080) | 0x8000; // Keep flags clean
        encoded = DnsPacket::encode(trimmedMessage);
    }
    
    return encoded;
}

void DnsServer::sendResponse(const std::vector<uint8_t>& response, const std::string& addr, uint16_t port, int tcpSocket) {
    if (tcpSocket >= 0) {
        sendTcpResponse(tcpSocket, response);
    } else {
        sendUdpResponse(response, addr, port);
    }
}

void DnsServer::handleDnsQuery(const std::vector<uint8_t>& msg, const std::string& clientAddr, uint16_t clientPort, int tcpSocket) {
    try {
        DnsMessage query = DnsPacket::decode(msg);
        
        if (query.questions.empty()) {
            sendErrorResponse(query, 1, clientAddr, clientPort, tcpSocket); // Format error
            return;
        }
        
        const auto& question = query.questions[0];
        std::string domain = question.name;
        DnsType type = question.type;
        
        std::cout << "DNS Query: " << domain << " (type: " << DnsPacket::typeToString(type) << ")" << std::endl;
        
        // Check for control domains (enable/disable overrides)
        if (handleControlDomain(query, domain, clientAddr, clientPort, tcpSocket)) {
            return;
        }
        
        // Check for domain override
        if (overridesEnabled_) {
            DomainOverride* override = findDomainOverride(domain);
            if (override) {
                std::cout << "Using override for domain: " << domain << std::endl;
                sendOverrideResponse(query, *override, clientAddr, clientPort, tcpSocket);
                return;
            }
        }
        
        // Proxy to upstream DNS
        std::cout << "Proxying to " << config_.upstreamDns << ": " << domain << std::endl;
        proxyToGoogleDns(query, clientAddr, clientPort, tcpSocket);
        
    } catch (const std::exception& e) {
        std::cerr << "Error handling DNS query: " << e.what() << std::endl;
        try {
            DnsMessage query = DnsPacket::decode(msg);
            sendErrorResponse(query, 2, clientAddr, clientPort, tcpSocket); // Server failure
        } catch (...) {
            // Ignore decode errors
        }
    }
}

DomainOverride* DnsServer::findDomainOverride(const std::string& domain) {
    for (auto& override : database_.overrides) {
        // Exact match
        if (override.domain == domain) {
            return &override;
        }
        
        // Wildcard match
        if (override.domain.length() >= 2 && override.domain.substr(0, 2) == "*.") {
            std::string wildcardDomain = override.domain.substr(2);
            if (domain.length() >= wildcardDomain.length() && 
                domain.substr(domain.length() - wildcardDomain.length()) == wildcardDomain) {
                return &override;
            }
        }
    }
    return nullptr;
}

void DnsServer::sendOverrideResponse(const DnsMessage& query, const DomainOverride& override, 
                                     const std::string& clientAddr, uint16_t clientPort, int tcpSocket) {
    DnsMessage response{};  // Zero-initialize all fields
    response.id = query.id;
    response.setResponse();
    response.setRecursionAvailable();
    response.questions = query.questions;
    
    // Convert override records to DNS answers
    for (const auto& record : override.records) {
        DnsAnswer answer;
        answer.name = record.name;
        answer.type = DnsPacket::stringToType(record.type);
        answer.class_ = DnsClass::IN;
        answer.ttl = record.ttl;
        answer.data = record.data;
        response.answers.push_back(answer);
    }
    
    std::vector<uint8_t> responseBuffer = ensureUdpSize(response, tcpSocket);
    sendResponse(responseBuffer, clientAddr, clientPort, tcpSocket);
}

void DnsServer::proxyToGoogleDns(const DnsMessage& query, const std::string& clientAddr, uint16_t clientPort, int tcpSocket) {
    // Create a new socket for proxying
    int proxySocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (proxySocket < 0) {
        std::cerr << "Failed to create proxy socket" << std::endl;
        sendErrorResponse(query, 2, clientAddr, clientPort, tcpSocket);
        return;
    }
    
    // Set timeout
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(proxySocket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    // Encode query
    std::vector<uint8_t> queryBuffer = DnsPacket::encode(query);
    
    // Send to upstream DNS
    struct sockaddr_in upstreamAddr;
    std::memset(&upstreamAddr, 0, sizeof(upstreamAddr));
    upstreamAddr.sin_family = AF_INET;
    upstreamAddr.sin_port = htons(53);
    
    if (inet_pton(AF_INET, config_.upstreamDns.c_str(), &upstreamAddr.sin_addr) <= 0) {
        std::cerr << "Invalid upstream DNS address: " << config_.upstreamDns << std::endl;
        close(proxySocket);
        sendErrorResponse(query, 2, clientAddr, clientPort, tcpSocket);
        return;
    }
    
    if (sendto(proxySocket, queryBuffer.data(), queryBuffer.size(), 0,
               reinterpret_cast<struct sockaddr*>(&upstreamAddr), sizeof(upstreamAddr)) < 0) {
        std::cerr << "Error sending to upstream DNS: " << strerror(errno) << std::endl;
        close(proxySocket);
        sendErrorResponse(query, 2, clientAddr, clientPort, tcpSocket);
        return;
    }
    
    // Receive response
    // Use larger buffer for UDP to handle EDNS0, but limit to reasonable size
    const size_t MAX_UDP_RESPONSE_SIZE = 4096;
    std::vector<uint8_t> responseBuffer(MAX_UDP_RESPONSE_SIZE);
    socklen_t addrLen = sizeof(upstreamAddr);
    ssize_t received = recvfrom(proxySocket, responseBuffer.data(), responseBuffer.size(), 0,
                                reinterpret_cast<struct sockaddr*>(&upstreamAddr), &addrLen);
    
    close(proxySocket);
    
    if (received < 0) {
        std::cerr << "Error receiving from upstream DNS: " << strerror(errno) << std::endl;
        sendErrorResponse(query, 2, clientAddr, clientPort, tcpSocket);
        return;
    }
    
    // Validate received size
    if (received > static_cast<ssize_t>(MAX_UDP_RESPONSE_SIZE)) {
        std::cerr << "Upstream response too large: " << received << " bytes" << std::endl;
        sendErrorResponse(query, 2, clientAddr, clientPort, tcpSocket);
        return;
    }
    
    responseBuffer.resize(received);
    
    // For UDP, ensure response fits in 512 bytes
    if (tcpSocket < 0 && responseBuffer.size() > 512) {
        // Decode, trim, and re-encode if needed
        try {
            DnsMessage upstreamResponse = DnsPacket::decode(responseBuffer);
            upstreamResponse.clearTruncated(); // Ensure TC flag is not set
            responseBuffer = ensureUdpSize(upstreamResponse, tcpSocket);
        } catch (...) {
            // If decode fails, just truncate to 512 bytes
            responseBuffer.resize(512);
        }
    }
    
    // Forward response to client
    sendResponse(responseBuffer, clientAddr, clientPort, tcpSocket);
}

void DnsServer::sendErrorResponse(const DnsMessage& query, uint8_t rcode, 
                                  const std::string& clientAddr, uint16_t clientPort, int tcpSocket) {
    try {
        DnsMessage response{};  // Zero-initialize all fields
        response.id = query.id;
        response.setResponse();
        response.setRecursionAvailable();
        response.setRCode(rcode);
        response.questions = query.questions;
        response.answers.clear();
        
        std::vector<uint8_t> responseBuffer = ensureUdpSize(response, tcpSocket);
        sendResponse(responseBuffer, clientAddr, clientPort, tcpSocket);
    } catch (const std::exception& e) {
        std::cerr << "Error sending error response: " << e.what() << std::endl;
    }
}

void DnsServer::setupHttpServer(uint16_t port) {
    httplib::Server svr;
    
    // CORS headers
    svr.set_default_headers({
        {"Access-Control-Allow-Origin", "*"},
        {"Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS"},
        {"Access-Control-Allow-Headers", "Content-Type"}
    });
    
    svr.Options(".*", [](const httplib::Request&, httplib::Response& res) {
        res.status = 200;
    });
    
    // Serve static HTML files for static overrides
    svr.Get("/static/:domain", [this](const httplib::Request& req, httplib::Response& res) {
        std::string domain = req.path_params.at("domain");
        
        // Find the override for this domain
        for (const auto& override : database_.overrides) {
            if (override.domain == domain && override.staticPort > 0 && !override.staticHtmlPath.empty()) {
                std::ifstream file(override.staticHtmlPath);
                if (file.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    res.set_content(content, "text/html");
                    file.close();
                    return;
                } else {
                    res.status = 404;
                    res.set_content("HTML file not found: " + override.staticHtmlPath, "text/plain");
                    return;
                }
            }
        }
        
        res.status = 404;
        res.set_content("Static override not found for domain: " + domain, "text/plain");
    });
    
    // Serve static viewer
    svr.Get("/static/:domain/viewer", [this](const httplib::Request& req, httplib::Response& res) {
        std::string domain = req.path_params.at("domain");
        
        // Find the override for this domain
        for (const auto& override : database_.overrides) {
            if (override.domain == domain && override.staticPort > 0) {
                std::string html = R"(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Static Override Viewer - )" + domain + R"(</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 0;
            background: #f5f5f5;
        }
        .container {
            width: 100%;
            height: 100vh;
            border: none;
        }
    </style>
</head>
<body>
    <iframe class="container" src="/static/)" + domain + R"(" frameborder="0"></iframe>
    <script>
        // Auto-refresh if the page fails to load
        window.addEventListener('load', function() {
            const iframe = document.querySelector('iframe');
            iframe.addEventListener('error', function() {
                setTimeout(() => location.reload(), 1000);
            });
        });
    </script>
</body>
</html>)";
                res.set_content(html, "text/html");
                return;
            }
        }
        
        res.status = 404;
        res.set_content("Static override not found for domain: " + domain, "text/plain");
    });
    
    // Serve web UI
    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        // Try multiple paths to find the HTML file
        std::vector<std::string> paths = {
            "cpp/web/index.html",
            "../cpp/web/index.html",
            "../../cpp/web/index.html",
            "web/index.html",
            "../web/index.html"
        };
        
        std::ifstream file;
        for (const auto& path : paths) {
            file.open(path);
            if (file.is_open()) {
                break;
            }
        }
        
        if (file.is_open()) {
            std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            res.set_content(content, "text/html");
            file.close();
        } else {
            // Fallback: serve embedded HTML
            std::string html = R"(<!DOCTYPE html>
<html><head><title>DNS Server</title></head>
<body><h1>DNS Server Web UI</h1>
<p>Web UI file not found. Please ensure cpp/web/index.html exists.</p>
<p>API endpoints:</p>
<ul>
<li>GET /api/status - Get server status</li>
<li>GET /api/domains - List all domains</li>
<li>POST /api/domains - Add domain</li>
<li>PUT /api/domains/:domain - Update domain</li>
<li>DELETE /api/domains/:domain - Delete domain</li>
</ul>
</body></html>)";
            res.set_content(html, "text/html");
        }
    });
    
    // Authentication check function
    auto requireAuth = [this](const httplib::Request& req, httplib::Response& res) -> bool {
        if (!checkAuth(req)) {
            res.status = 401;
            json response = {
                {"status", "error"},
                {"message", "Authentication required"},
                {"requiresAuth", !config_.adminPassword.empty()}
            };
            res.set_content(response.dump(), "application/json");
            return false;
        }
        return true;
    };
    
    // Login endpoint
    svr.Post("/api/login", [this](const httplib::Request& req, httplib::Response& res) {
        // If no password is set, allow access
        if (config_.adminPassword.empty()) {
            json response = {
                {"status", "success"},
                {"authenticated", true},
                {"message", "No password required"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        try {
            json body = json::parse(req.body);
            std::string password = body.value("password", "");
            
            if (password == config_.adminPassword) {
                // Set a simple session cookie (in production, use proper session tokens)
                res.set_header("Set-Cookie", "authenticated=true; Path=/; HttpOnly; SameSite=Strict");
                json response = {
                    {"status", "success"},
                    {"authenticated", true}
                };
                res.set_content(response.dump(), "application/json");
            } else {
                res.status = 401;
                json response = {
                    {"status", "error"},
                    {"message", "Invalid password"}
                };
                res.set_content(response.dump(), "application/json");
            }
        } catch (const std::exception& e) {
            res.status = 400;
            json response = {
                {"status", "error"},
                {"message", "Invalid request"}
            };
            res.set_content(response.dump(), "application/json");
        }
    });
    
    // Check auth status
    svr.Get("/api/auth-status", [this](const httplib::Request& req, httplib::Response& res) {
        bool requiresAuth = !config_.adminPassword.empty();
        bool authenticated = requiresAuth ? checkAuth(req) : true;
        
        json response = {
            {"status", "success"},
            {"requiresAuth", requiresAuth},
            {"authenticated", authenticated}
        };
        res.set_content(response.dump(), "application/json");
    });
    
    // API: Get status
    svr.Get("/api/status", [this, requireAuth](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res)) return;
        json response = {
            {"status", "success"},
            {"overridesEnabled", overridesEnabled_.load()},
            {"dnsWhitelistEnabled", config_.dnsWhitelistEnabled}
        };
        res.set_content(response.dump(), "application/json");
    });

    // API: Get DNS whitelist IPs
    svr.Get("/api/whitelist", [this, requireAuth](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res)) return;
        std::vector<std::string> ips;
        {
            std::lock_guard<std::mutex> lock(dnsWhitelistMutex_);
            ips = database_.dnsWhitelistIps;
        }
        json response = {
            {"status", "success"},
            {"dnsWhitelistEnabled", config_.dnsWhitelistEnabled},
            {"ips", ips}
        };
        res.set_content(response.dump(), "application/json");
    });

    // API: Add DNS whitelist IP
    svr.Post("/api/whitelist", [this, requireAuth](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res)) return;
        try {
            json body = json::parse(req.body);
            std::string ip = body.value("ip", "");
            if (!isValidIpv4Address(ip)) {
                res.status = 400;
                json response = {
                    {"status", "error"},
                    {"message", "Invalid IPv4 address"}
                };
                res.set_content(response.dump(), "application/json");
                return;
            }

            bool added = false;
            {
                std::lock_guard<std::mutex> lock(dnsWhitelistMutex_);
                auto it = std::find(database_.dnsWhitelistIps.begin(), database_.dnsWhitelistIps.end(), ip);
                if (it == database_.dnsWhitelistIps.end()) {
                    database_.dnsWhitelistIps.push_back(ip);
                    dnsWhitelistIps_.insert(ip);
                    added = true;
                }
            }

            if (added) {
                saveDatabase();
            }

            json response = {
                {"status", "success"},
                {"message", added ? "IP added to whitelist" : "IP already in whitelist"}
            };
            res.set_content(response.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            json response = {
                {"status", "error"},
                {"message", std::string("Invalid request: ") + e.what()}
            };
            res.set_content(response.dump(), "application/json");
        }
    });

    // API: Remove DNS whitelist IP
    svr.Delete("/api/whitelist/:ip", [this, requireAuth](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res)) return;
        std::string ip = req.path_params.at("ip");
        bool removed = false;
        {
            std::lock_guard<std::mutex> lock(dnsWhitelistMutex_);
            auto it = std::remove(database_.dnsWhitelistIps.begin(), database_.dnsWhitelistIps.end(), ip);
            if (it != database_.dnsWhitelistIps.end()) {
                database_.dnsWhitelistIps.erase(it, database_.dnsWhitelistIps.end());
                dnsWhitelistIps_.erase(ip);
                removed = true;
            }
        }

        if (removed) {
            saveDatabase();
        }

        json response = {
            {"status", "success"},
            {"message", removed ? "IP removed from whitelist" : "IP not found in whitelist"}
        };
        res.set_content(response.dump(), "application/json");
    });

    // API: Get recent blocked whitelist attempts
    svr.Get("/api/whitelist-blocked", [this, requireAuth](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res)) return;
        json attempts = json::array();
        {
            std::lock_guard<std::mutex> lock(blockedAttemptsMutex_);
            for (auto it = blockedWhitelistAttempts_.rbegin(); it != blockedWhitelistAttempts_.rend(); ++it) {
                attempts.push_back(json::parse(*it));
            }
        }

        json response = {
            {"status", "success"},
            {"dnsWhitelistEnabled", config_.dnsWhitelistEnabled},
            {"blockedAttempts", attempts}
        };
        res.set_content(response.dump(), "application/json");
    });
    
    // API: Get all domains
    svr.Get("/api/domains", [this, requireAuth](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res)) return;
        json response;
        response["status"] = "success";
        response["domains"] = json::array();
        
        for (const auto& override : database_.overrides) {
            json domainJson;
            domainJson["domain"] = override.domain;
            domainJson["records"] = json::array();
            
            for (const auto& record : override.records) {
                json recordJson;
                recordJson["type"] = record.type;
                recordJson["name"] = record.name;
                recordJson["data"] = record.data;
                recordJson["ttl"] = record.ttl;
                domainJson["records"].push_back(recordJson);
            }
            
            if (override.staticPort > 0) {
                domainJson["staticPort"] = override.staticPort;
            }
            if (!override.staticHtmlPath.empty()) {
                domainJson["staticHtmlPath"] = override.staticHtmlPath;
            }
            
            response["domains"].push_back(domainJson);
        }
        
        res.set_content(response.dump(), "application/json");
    });
    
    // API: Get single domain
    svr.Get("/api/domains/:domain", [this, requireAuth](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res)) return;
        std::string domain = req.path_params.at("domain");
        
        for (const auto& override : database_.overrides) {
            if (override.domain == domain) {
                json response;
                response["status"] = "success";
                response["domain"]["domain"] = override.domain;
                response["domain"]["records"] = json::array();
                
                for (const auto& record : override.records) {
                    json recordJson;
                    recordJson["type"] = record.type;
                    recordJson["name"] = record.name;
                    recordJson["data"] = record.data;
                    recordJson["ttl"] = record.ttl;
                    response["domain"]["records"].push_back(recordJson);
                }
                
                if (override.staticPort > 0) {
                    response["domain"]["staticPort"] = override.staticPort;
                }
                if (!override.staticHtmlPath.empty()) {
                    response["domain"]["staticHtmlPath"] = override.staticHtmlPath;
                }
                
                res.set_content(response.dump(), "application/json");
                return;
            }
        }
        
        res.status = 404;
        json response = {
            {"status", "error"},
            {"message", "Domain not found"}
        };
        res.set_content(response.dump(), "application/json");
    });
    
    // API: Add domain
    svr.Post("/api/domains", [this, requireAuth](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res)) return;
        try {
            json body = json::parse(req.body);
            
            DomainOverride override;
            override.domain = body["domain"].get<std::string>();
            
            if (body.contains("records") && body["records"].is_array()) {
                for (const auto& recordJson : body["records"]) {
                    DnsRecord record;
                    record.type = recordJson["type"].get<std::string>();
                    record.name = recordJson["name"].get<std::string>();
                    record.data = recordJson["data"].get<std::string>();
                    if (recordJson.contains("ttl")) {
                        record.ttl = recordJson["ttl"].get<uint32_t>();
                    } else {
                        record.ttl = 300;
                    }
                    override.records.push_back(record);
                }
            }
            
            if (body.contains("staticPort")) {
                override.staticPort = body["staticPort"].get<uint16_t>();
            }
            if (body.contains("staticHtmlPath")) {
                override.staticHtmlPath = body["staticHtmlPath"].get<std::string>();
            }
            
            if (addDomainOverride(override)) {
                json response = {
                    {"status", "success"},
                    {"message", "Domain added successfully"}
                };
                res.set_content(response.dump(), "application/json");
            } else {
                res.status = 400;
                json response = {
                    {"status", "error"},
                    {"message", "Domain already exists"}
                };
                res.set_content(response.dump(), "application/json");
            }
        } catch (const std::exception& e) {
            res.status = 400;
            json response = {
                {"status", "error"},
                {"message", std::string("Invalid request: ") + e.what()}
            };
            res.set_content(response.dump(), "application/json");
        }
    });
    
    // API: Update domain
    svr.Put("/api/domains/:domain", [this, requireAuth](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res)) return;
        try {
            std::string domain = req.path_params.at("domain");
            json body = json::parse(req.body);
            
            DomainOverride override;
            override.domain = body["domain"].get<std::string>();
            
            if (body.contains("records") && body["records"].is_array()) {
                for (const auto& recordJson : body["records"]) {
                    DnsRecord record;
                    record.type = recordJson["type"].get<std::string>();
                    record.name = recordJson["name"].get<std::string>();
                    record.data = recordJson["data"].get<std::string>();
                    if (recordJson.contains("ttl")) {
                        record.ttl = recordJson["ttl"].get<uint32_t>();
                    } else {
                        record.ttl = 300;
                    }
                    override.records.push_back(record);
                }
            }
            
            if (body.contains("staticPort")) {
                override.staticPort = body["staticPort"].get<uint16_t>();
            }
            if (body.contains("staticHtmlPath")) {
                override.staticHtmlPath = body["staticHtmlPath"].get<std::string>();
            }
            
            if (updateDomainOverride(domain, override)) {
                json response = {
                    {"status", "success"},
                    {"message", "Domain updated successfully"}
                };
                res.set_content(response.dump(), "application/json");
            } else {
                res.status = 404;
                json response = {
                    {"status", "error"},
                    {"message", "Domain not found"}
                };
                res.set_content(response.dump(), "application/json");
            }
        } catch (const std::exception& e) {
            res.status = 400;
            json response = {
                {"status", "error"},
                {"message", std::string("Invalid request: ") + e.what()}
            };
            res.set_content(response.dump(), "application/json");
        }
    });
    
    // API: Delete domain
    svr.Delete("/api/domains/:domain", [this, requireAuth](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res)) return;
        std::string domain = req.path_params.at("domain");
        
        if (deleteDomainOverride(domain)) {
            json response = {
                {"status", "success"},
                {"message", "Domain deleted successfully"}
            };
            res.set_content(response.dump(), "application/json");
        } else {
            res.status = 404;
            json response = {
                {"status", "error"},
                {"message", "Domain not found"}
            };
            res.set_content(response.dump(), "application/json");
        }
    });
    
    // API: Save HTML file
    svr.Post("/api/save-html", [requireAuth](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res)) return;
        try {
            json body = json::parse(req.body);
            std::string path = body["path"].get<std::string>();
            std::string content = body["content"].get<std::string>();
            
            // Create directory if it doesn't exist
            size_t lastSlash = path.find_last_of("/");
            if (lastSlash != std::string::npos) {
                std::string dir = path.substr(0, lastSlash);
                try {
                    std::filesystem::create_directories(dir);
                } catch (const std::exception&) {
                    // Ignore errors, try to write file anyway
                }
            }
            
            // Write file
            std::ofstream file(path);
            if (!file.is_open()) {
                res.status = 500;
                json response = {
                    {"status", "error"},
                    {"message", "Could not open file for writing: " + path}
                };
                res.set_content(response.dump(), "application/json");
                return;
            }
            
            file << content;
            file.close();
            
            json response = {
                {"status", "success"},
                {"message", "HTML file saved successfully"}
            };
            res.set_content(response.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            json response = {
                {"status", "error"},
                {"message", std::string("Invalid request: ") + e.what()}
            };
            res.set_content(response.dump(), "application/json");
        }
    });
    
    // API: Load HTML file
    svr.Get("/api/load-html", [requireAuth](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res)) return;
        try {
            std::string path = req.get_param_value("path");
            if (path.empty()) {
                res.status = 400;
                json response = {
                    {"status", "error"},
                    {"message", "Path parameter required"}
                };
                res.set_content(response.dump(), "application/json");
                return;
            }
            
            std::ifstream file(path);
            if (!file.is_open()) {
                res.status = 404;
                json response = {
                    {"status", "error"},
                    {"message", "File not found: " + path}
                };
                res.set_content(response.dump(), "application/json");
                return;
            }
            
            std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            file.close();
            
            json response = {
                {"status", "success"},
                {"content", content}
            };
            res.set_content(response.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 500;
            json response = {
                {"status", "error"},
                {"message", std::string("Error reading file: ") + e.what()}
            };
            res.set_content(response.dump(), "application/json");
        }
    });
    
    svr.Get("/enable-overrides", [this](const httplib::Request&, httplib::Response& res) {
        overridesEnabled_ = true;
        json response = {
            {"status", "success"},
            {"message", "Overrides enabled"},
            {"overridesEnabled", true}
        };
        res.set_content(response.dump(), "application/json");
        std::cout << "Overrides enabled via HTTP endpoint" << std::endl;
    });
    
    svr.Get("/disable-overrides", [this](const httplib::Request&, httplib::Response& res) {
        overridesEnabled_ = false;
        json response = {
            {"status", "success"},
            {"message", "Overrides disabled"},
            {"overridesEnabled", false}
        };
        res.set_content(response.dump(), "application/json");
        std::cout << "Overrides disabled via HTTP endpoint" << std::endl;
    });
    
    std::cout << "HTTP Server listening on 0.0.0.0:" << port << std::endl;
    svr.listen("0.0.0.0", port);
}

void DnsServer::setupStaticHttpServer(uint16_t httpPort) {
    // Start a server for each static override
    // Note: This starts servers based on the database at startup
    // To add new static overrides, restart the server or implement dynamic server management
    // Skip creating separate servers for ports that match the main HTTP server port
    // (those are served through the main server on /static/:domain routes)
    
    std::vector<std::unique_ptr<std::thread>> serverThreads;
    
    // Create servers for all static overrides
    for (const auto& override : database_.overrides) {
        if (override.staticPort > 0 && !override.staticHtmlPath.empty() && override.staticPort != httpPort) {
            std::string htmlPath = override.staticHtmlPath;
            std::string domain = override.domain;
            uint16_t port = override.staticPort;
            
            serverThreads.push_back(std::make_unique<std::thread>([htmlPath, domain, port]() {
                httplib::Server svr;
                
                // CORS headers
                svr.set_default_headers({
                    {"Access-Control-Allow-Origin", "*"},
                    {"Access-Control-Allow-Methods", "GET, OPTIONS"},
                    {"Access-Control-Allow-Headers", "Content-Type"}
                });
                
                svr.Options(".*", [](const httplib::Request&, httplib::Response& res) {
                    res.status = 200;
                });
                
                // Serve the HTML file
                svr.Get("/", [htmlPath](const httplib::Request&, httplib::Response& res) {
                    std::ifstream file(htmlPath);
                    if (file.is_open()) {
                        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                        res.set_content(content, "text/html");
                        file.close();
                    } else {
                        res.status = 404;
                        res.set_content("HTML file not found: " + htmlPath, "text/plain");
                    }
                });
                
                // Serve static viewer that opens the correct HTML
                svr.Get("/viewer", [domain](const httplib::Request&, httplib::Response& res) {
                    std::string html = R"(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Static Override Viewer - )" + domain + R"(</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 0;
            background: #f5f5f5;
        }
        .container {
            width: 100%;
            height: 100vh;
            border: none;
        }
    </style>
</head>
<body>
    <iframe class="container" src="/" frameborder="0"></iframe>
    <script>
        // Auto-refresh if the page fails to load
        window.addEventListener('load', function() {
            const iframe = document.querySelector('iframe');
            iframe.addEventListener('error', function() {
                setTimeout(() => location.reload(), 1000);
            });
        });
    </script>
</body>
</html>)";
                    res.set_content(html, "text/html");
                });
                
                std::cout << "Static HTTP Server listening on 0.0.0.0:" << port << " for static override: " << domain << std::endl;
                svr.listen("0.0.0.0", port);
            }));
        }
    }
    
    // Wait while running
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    // Join all threads (servers will stop when the process exits)
    for (auto& thread : serverThreads) {
        if (thread && thread->joinable()) {
            thread->join();
        }
    }
}

void DnsServer::start(uint16_t httpPort) {
    running_ = true;
    setupUdpServer();
    setupTcpServer();
    
    // Start HTTP server in separate thread
    httpThread_ = std::make_unique<std::thread>(&DnsServer::setupHttpServer, this, httpPort);
    
    // Start static HTTP server in separate thread
    staticHttpThread_ = std::make_unique<std::thread>(&DnsServer::setupStaticHttpServer, this, httpPort);
    
    // Start TCP server in separate thread
    tcpThread_ = std::make_unique<std::thread>([this]() {
        while (running_) {
            struct sockaddr_in clientAddr;
            socklen_t clientAddrLen = sizeof(clientAddr);
            int clientSocket = accept(tcpSocket_, reinterpret_cast<struct sockaddr*>(&clientAddr), &clientAddrLen);
            
            if (clientSocket < 0) {
                if (running_) {
                    std::cerr << "Error accepting TCP connection: " << strerror(errno) << std::endl;
                }
                continue;
            }
            
            // Handle each connection in the same thread (simple approach)
            // For production, you might want to spawn a new thread per connection
            handleTcpConnection(clientSocket);
        }
    });
    
    // Main UDP loop
    // DNS spec allows up to 512 bytes for UDP, but we use 1024 to handle EDNS0 extensions
    const size_t UDP_BUFFER_SIZE = 1024;
    std::vector<uint8_t> buffer(UDP_BUFFER_SIZE);
    struct sockaddr_in clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);
    
    while (running_) {
        ssize_t received = recvfrom(udpSocket_, buffer.data(), buffer.size(), 0,
                                   reinterpret_cast<struct sockaddr*>(&clientAddr), &clientAddrLen);
        
        if (received < 0) {
            if (running_) {
                std::cerr << "Error receiving UDP packet: " << strerror(errno) << std::endl;
            }
            continue;
        }
        
        // Validate received packet size
        if (received > static_cast<ssize_t>(buffer.size())) {
            std::cerr << "Received packet larger than buffer: " << received << " bytes" << std::endl;
            continue;
        }
        
        char clientIp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIp, INET_ADDRSTRLEN);
        uint16_t clientPort = ntohs(clientAddr.sin_port);
        std::vector<uint8_t> msg(buffer.begin(), buffer.begin() + received);

        if (!isDnsClientAllowed(std::string(clientIp))) {
            std::string domain = extractDnsDomain(msg);
            std::cout << "Blocked UDP DNS client (not in whitelist): " << clientIp << std::endl;
            logBlockedWhitelistAttempt("UDP", std::string(clientIp), domain);
            continue;
        }

        handleDnsQuery(msg, std::string(clientIp), clientPort);
    }
}

void DnsServer::stop() {
    running_ = false;
    
    if (udpSocket_ >= 0) {
        close(udpSocket_);
        udpSocket_ = -1;
    }
    
    if (tcpSocket_ >= 0) {
        close(tcpSocket_);
        tcpSocket_ = -1;
    }
    
    if (httpThread_ && httpThread_->joinable()) {
        httpThread_->join();
    }
    
    if (staticHttpThread_ && staticHttpThread_->joinable()) {
        staticHttpThread_->join();
    }
    
    if (tcpThread_ && tcpThread_->joinable()) {
        tcpThread_->join();
    }
}

void DnsServer::reloadDatabase() {
    loadDatabase();
    std::cout << "Database reloaded" << std::endl;
}

void DnsServer::saveDatabase() {
    try {
        json j;
        j["dnsWhitelistIps"] = json::array();
        std::vector<std::string> whitelistIps;
        {
            std::lock_guard<std::mutex> lock(dnsWhitelistMutex_);
            whitelistIps = database_.dnsWhitelistIps;
        }
        for (const auto& ip : whitelistIps) {
            j["dnsWhitelistIps"].push_back(ip);
        }
        j["overrides"] = json::array();
        
        for (const auto& override : database_.overrides) {
            json overrideJson;
            overrideJson["domain"] = override.domain;
            overrideJson["records"] = json::array();
            
            for (const auto& record : override.records) {
                json recordJson;
                recordJson["type"] = record.type;
                recordJson["name"] = record.name;
                recordJson["data"] = record.data;
                recordJson["ttl"] = record.ttl;
                overrideJson["records"].push_back(recordJson);
            }
            
            if (override.staticPort > 0) {
                overrideJson["staticPort"] = override.staticPort;
            }
            if (!override.staticHtmlPath.empty()) {
                overrideJson["staticHtmlPath"] = override.staticHtmlPath;
            }
            
            j["overrides"].push_back(overrideJson);
        }
        
        std::ofstream file(config_.databasePath);
        if (!file.is_open()) {
            throw std::runtime_error("Could not open database file for writing: " + config_.databasePath);
        }
        
        file << j.dump(2); // Pretty print with 2-space indent
        file.close();
        
        std::cout << "Database saved to " << config_.databasePath << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error saving database: " << e.what() << std::endl;
        throw;
    }
}

bool DnsServer::addDomainOverride(const DomainOverride& override) {
    // Check if domain already exists
    for (const auto& existing : database_.overrides) {
        if (existing.domain == override.domain) {
            return false; // Domain already exists
        }
    }
    
    database_.overrides.push_back(override);
    saveDatabase();
    return true;
}

bool DnsServer::updateDomainOverride(const std::string& domain, const DomainOverride& override) {
    for (auto& existing : database_.overrides) {
        if (existing.domain == domain) {
            existing = override;
            saveDatabase();
            return true;
        }
    }
    return false; // Domain not found
}

bool DnsServer::deleteDomainOverride(const std::string& domain) {
    // Find the override first to check for static file
    DomainOverride* overrideToDelete = nullptr;
    for (auto& override : database_.overrides) {
        if (override.domain == domain) {
            overrideToDelete = &override;
            break;
        }
    }
    
    if (overrideToDelete) {
        // Delete static HTML file if it exists
        if (!overrideToDelete->staticHtmlPath.empty()) {
            try {
                // Only delete files in the data/static directory for safety
                if (overrideToDelete->staticHtmlPath.find("data/static/") == 0 || 
                    overrideToDelete->staticHtmlPath.find("./data/static/") == 0) {
                    if (std::filesystem::exists(overrideToDelete->staticHtmlPath)) {
                        std::filesystem::remove(overrideToDelete->staticHtmlPath);
                        std::cout << "Deleted static HTML file: " << overrideToDelete->staticHtmlPath << std::endl;
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "Warning: Could not delete static HTML file: " << e.what() << std::endl;
                // Continue with domain deletion even if file deletion fails
            }
        }
        
        // Remove the override from database
    auto it = std::remove_if(database_.overrides.begin(), database_.overrides.end(),
        [&domain](const DomainOverride& override) {
            return override.domain == domain;
        });
    
    if (it != database_.overrides.end()) {
        database_.overrides.erase(it, database_.overrides.end());
        saveDatabase();
        return true;
    }
    }
    
    return false; // Domain not found
}

bool DnsServer::checkAuth(const httplib::Request& req) {
    // If no password is set, allow access
    if (config_.adminPassword.empty()) {
        return true;
    }
    
    // Check for authentication cookie
    auto cookies = req.get_header_value("Cookie");
    if (!cookies.empty()) {
        size_t pos = cookies.find("authenticated=true");
        if (pos != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

bool DnsServer::isDnsClientAllowed(const std::string& clientAddr) const {
    if (!config_.dnsWhitelistEnabled) {
        return true;
    }
    std::lock_guard<std::mutex> lock(dnsWhitelistMutex_);
    return dnsWhitelistIps_.find(clientAddr) != dnsWhitelistIps_.end();
}

bool DnsServer::handleControlDomain(const DnsMessage& query, const std::string& domain, 
                                    const std::string& clientAddr, uint16_t clientPort, int tcpSocket) {
    // Check for enable.control.dns.local
    if (domain == "enable.control.dns.local") {
        overridesEnabled_ = true;
        std::cout << "Overrides enabled via DNS control domain from " << clientAddr << std::endl;
        sendControlResponse(query, domain, true, clientAddr, clientPort, tcpSocket);
        return true;
    }
    
    // Check for disable.control.dns.local
    if (domain == "disable.control.dns.local") {
        overridesEnabled_ = false;
        std::cout << "Overrides disabled via DNS control domain from " << clientAddr << std::endl;
        sendControlResponse(query, domain, false, clientAddr, clientPort, tcpSocket);
        return true;
    }
    
    return false;
}

void DnsServer::sendControlResponse(const DnsMessage& query, const std::string& domain, bool enabled,
                                    const std::string& clientAddr, uint16_t clientPort, int tcpSocket) {
    DnsMessage response{};  // Zero-initialize all fields
    response.id = query.id;
    response.setResponse();
    response.setRecursionAvailable();
    response.questions = query.questions;
    
    // Return an A record with 127.0.0.1 to indicate success
    // The IP can be used to indicate status: 127.0.0.1 = enabled, 127.0.0.2 = disabled
    DnsAnswer answer;
    answer.name = domain;
    answer.type = DnsType::A;
    answer.class_ = DnsClass::IN;
    answer.ttl = 0; // No caching for control responses
    answer.data = enabled ? "127.0.0.1" : "127.0.0.2";
    response.answers.push_back(answer);
    
    std::vector<uint8_t> responseBuffer = ensureUdpSize(response, tcpSocket);
    sendResponse(responseBuffer, clientAddr, clientPort, tcpSocket);
}

