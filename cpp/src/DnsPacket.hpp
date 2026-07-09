#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "types.hpp"

// DNS record types
enum class DnsType : uint16_t {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28
};

// DNS classes
enum class DnsClass : uint16_t {
    IN = 1
};

struct DnsQuestion {
    std::string name;
    DnsType type;
    DnsClass class_;
};

struct DnsAnswer {
    std::string name;
    DnsType type;
    DnsClass class_;
    uint32_t ttl;
    std::string data;
};

struct DnsMessage {
    uint16_t id;
    uint16_t flags;
    std::vector<DnsQuestion> questions;
    std::vector<DnsAnswer> answers;
    std::vector<DnsAnswer> authority;
    std::vector<DnsAnswer> additional;
    
    bool isResponse() const { return (flags & 0x8000) != 0; }
    bool isQuery() const { return !isResponse(); }
    uint8_t getRCode() const { return flags & 0x000F; }
    void setRCode(uint8_t rcode) { flags = (flags & 0xFFF0) | (rcode & 0x000F); }
    void setResponse() { flags |= 0x8000; }
    void setRecursionAvailable() { flags |= 0x0080; }
    bool isTruncated() const { return (flags & 0x0200) != 0; }
    void setTruncated() { flags |= 0x0200; }
    void clearTruncated() { flags &= ~0x0200; }
};

class DnsPacket {
public:
    // Decode DNS packet from buffer
    static DnsMessage decode(const std::vector<uint8_t>& buffer);
    
    // Encode DNS message to buffer
    static std::vector<uint8_t> encode(const DnsMessage& message);
    
    // Convert string DNS type to enum
    static DnsType stringToType(const std::string& type);
    
    // Convert enum DNS type to string
    static std::string typeToString(DnsType type);
    
    // Convert string to DNS record data bytes
    static std::vector<uint8_t> encodeRecordData(DnsType type, const std::string& data);
    
    // Decode DNS record data bytes to string
    static std::string decodeRecordData(DnsType type, const std::vector<uint8_t>& data, size_t offset, size_t length);

private:
    // Helper functions for DNS name encoding/decoding
    static std::string decodeName(const std::vector<uint8_t>& buffer, size_t& offset);
    static void encodeName(std::vector<uint8_t>& buffer, const std::string& name);
    static uint16_t readUint16(const std::vector<uint8_t>& buffer, size_t& offset);
    static uint32_t readUint32(const std::vector<uint8_t>& buffer, size_t& offset);
    static void writeUint16(std::vector<uint8_t>& buffer, uint16_t value);
    static void writeUint32(std::vector<uint8_t>& buffer, uint32_t value);
};

