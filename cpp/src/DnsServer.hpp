#pragma once

#include "types.hpp"
#include <string>
#include <thread>
#include <atomic>
#include <memory>
#include <cstdint>
#include <vector>
#include <unordered_set>
#include <deque>
#include <mutex>

// Forward declarations
struct DnsMessage;

// Include httplib for Request type (header-only library)
#include <httplib.h>

class DnsServer {
public:
    explicit DnsServer(const DnsServerConfig& config);
    ~DnsServer();
    
    void start(uint16_t httpPort = 4167);
    void stop();
    void reloadDatabase();
    void saveDatabase();
    bool addDomainOverride(const DomainOverride& override);
    bool updateDomainOverride(const std::string& domain, const DomainOverride& override);
    bool deleteDomainOverride(const std::string& domain);
    const DnsDatabase& getDatabase() const { return database_; }
    
private:
    DnsServerConfig config_;
    DnsDatabase database_;
    std::atomic<bool> overridesEnabled_;
    
    int udpSocket_;
    int tcpSocket_;
    std::unique_ptr<std::thread> httpThread_;
    std::unique_ptr<std::thread> staticHttpThread_;
    std::unique_ptr<std::thread> tcpThread_;
    std::atomic<bool> running_;
    std::unordered_set<std::string> dnsWhitelistIps_;
    mutable std::mutex dnsWhitelistMutex_;
    std::deque<std::string> blockedWhitelistAttempts_;
    mutable std::mutex blockedAttemptsMutex_;
    
    void loadDatabase();
    void setupUdpServer();
    void setupTcpServer();
    void handleTcpConnection(int clientSocket);
    void sendTcpResponse(int clientSocket, const std::vector<uint8_t>& response);
    void handleDnsQuery(const std::vector<uint8_t>& msg, const std::string& clientAddr, uint16_t clientPort, int tcpSocket = -1);
    DomainOverride* findDomainOverride(const std::string& domain);
    void sendOverrideResponse(const DnsMessage& query, const DomainOverride& override, 
                             const std::string& clientAddr, uint16_t clientPort, int tcpSocket = -1);
    void proxyToGoogleDns(const DnsMessage& query, const std::string& clientAddr, uint16_t clientPort, int tcpSocket = -1);
    void sendErrorResponse(const DnsMessage& query, uint8_t rcode, 
                          const std::string& clientAddr, uint16_t clientPort, int tcpSocket = -1);
    void setupHttpServer(uint16_t port);
    void setupStaticHttpServer(uint16_t httpPort);
    void sendUdpResponse(const std::vector<uint8_t>& response, const std::string& addr, uint16_t port);
    void sendResponse(const std::vector<uint8_t>& response, const std::string& addr, uint16_t port, int tcpSocket = -1);
    std::vector<uint8_t> ensureUdpSize(const DnsMessage& message, int tcpSocket);
    bool handleControlDomain(const DnsMessage& query, const std::string& domain, 
                             const std::string& clientAddr, uint16_t clientPort, int tcpSocket = -1);
    void sendControlResponse(const DnsMessage& query, const std::string& domain, bool enabled,
                            const std::string& clientAddr, uint16_t clientPort, int tcpSocket = -1);
    bool checkAuth(const httplib::Request& req);
    bool isDnsClientAllowed(const std::string& clientAddr) const;
    void logBlockedWhitelistAttempt(const std::string& protocol, const std::string& clientAddr, const std::string& domain);
};

