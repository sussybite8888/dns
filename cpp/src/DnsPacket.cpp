#include "DnsPacket.hpp"
#include <cstring>
#include <sstream>
#include <algorithm>
#include <stdexcept>
#include <arpa/inet.h>

DnsType DnsPacket::stringToType(const std::string& type) {
    std::string upper = type;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
    
    if (upper == "A") return DnsType::A;
    if (upper == "NS") return DnsType::NS;
    if (upper == "CNAME") return DnsType::CNAME;
    if (upper == "SOA") return DnsType::SOA;
    if (upper == "PTR") return DnsType::PTR;
    if (upper == "MX") return DnsType::MX;
    if (upper == "TXT") return DnsType::TXT;
    if (upper == "AAAA") return DnsType::AAAA;
    return DnsType::A; // Default
}

std::string DnsPacket::typeToString(DnsType type) {
    switch (type) {
        case DnsType::A: return "A";
        case DnsType::NS: return "NS";
        case DnsType::CNAME: return "CNAME";
        case DnsType::SOA: return "SOA";
        case DnsType::PTR: return "PTR";
        case DnsType::MX: return "MX";
        case DnsType::TXT: return "TXT";
        case DnsType::AAAA: return "AAAA";
        default: return "A";
    }
}

uint16_t DnsPacket::readUint16(const std::vector<uint8_t>& buffer, size_t& offset) {
    if (offset + 2 > buffer.size()) {
        throw std::runtime_error("Buffer overflow reading uint16");
    }
    uint16_t value = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;
    return value;
}

uint32_t DnsPacket::readUint32(const std::vector<uint8_t>& buffer, size_t& offset) {
    if (offset + 4 > buffer.size()) {
        throw std::runtime_error("Buffer overflow reading uint32");
    }
    uint32_t value = (buffer[offset] << 24) | (buffer[offset + 1] << 16) | 
                     (buffer[offset + 2] << 8) | buffer[offset + 3];
    offset += 4;
    return value;
}

void DnsPacket::writeUint16(std::vector<uint8_t>& buffer, uint16_t value) {
    buffer.push_back((value >> 8) & 0xFF);
    buffer.push_back(value & 0xFF);
}

void DnsPacket::writeUint32(std::vector<uint8_t>& buffer, uint32_t value) {
    buffer.push_back((value >> 24) & 0xFF);
    buffer.push_back((value >> 16) & 0xFF);
    buffer.push_back((value >> 8) & 0xFF);
    buffer.push_back(value & 0xFF);
}

std::string DnsPacket::decodeName(const std::vector<uint8_t>& buffer, size_t& offset) {
    std::string name;
    size_t startOffset = offset;
    bool jumped = false;
    int jumps = 0;
    const int maxJumps = 5; // Prevent infinite loops
    const size_t MAX_NAME_LENGTH = 255; // DNS spec: max 255 bytes for domain name
    size_t totalNameLength = 0;
    
    while (offset < buffer.size() && jumps < maxJumps) {
        // Check bounds before reading
        if (offset >= buffer.size()) {
            throw std::runtime_error("Buffer overflow: offset beyond buffer size");
        }
        
        uint8_t len = buffer[offset++];
        
        if (len == 0) {
            break;
        }
        
        // Check for compression pointer
        if ((len & 0xC0) == 0xC0) {
            // Validate compression pointer
            if (offset >= buffer.size()) {
                throw std::runtime_error("Buffer overflow: incomplete compression pointer");
            }
            
            size_t compressionOffset = ((len & 0x3F) << 8) | buffer[offset];
            
            // Validate compression pointer points to valid location
            if (compressionOffset >= buffer.size() || compressionOffset < 12) {
                throw std::runtime_error("Invalid compression pointer: out of bounds");
            }
            
            // Prevent infinite loops: compression pointer must point backwards
            if (compressionOffset >= offset - 2) {
                throw std::runtime_error("Invalid compression pointer: must point backwards");
            }
            
            if (!jumped) {
                startOffset = offset + 1;
            }
            offset = compressionOffset;
            jumped = true;
            jumps++;
            continue;
        }
        
        if (len > 63) {
            throw std::runtime_error("Invalid name length: label exceeds 63 bytes");
        }
        
        // Check bounds before reading label
        if (offset + len > buffer.size()) {
            throw std::runtime_error("Buffer overflow: label extends beyond buffer");
        }
        
        // Check total name length (DNS spec: max 255 bytes)
        totalNameLength += len + 1; // +1 for the dot or null terminator
        if (totalNameLength > MAX_NAME_LENGTH) {
            throw std::runtime_error("Domain name too long: exceeds 255 bytes");
        }
        
        if (!name.empty()) {
            name += ".";
        }
        
        name.append(reinterpret_cast<const char*>(&buffer[offset]), len);
        offset += len;
    }
    
    if (jumped) {
        offset = startOffset;
    }
    
    return name;
}

void DnsPacket::encodeName(std::vector<uint8_t>& buffer, const std::string& name) {
    if (name.empty()) {
        buffer.push_back(0);
        return;
    }
    
    // DNS spec: max 255 bytes for domain name (including length bytes and null terminator)
    const size_t MAX_NAME_LENGTH = 255;
    if (name.length() > MAX_NAME_LENGTH - 1) { // -1 for null terminator
        throw std::runtime_error("Domain name too long: exceeds 255 bytes");
    }
    
    size_t start = 0;
    size_t encodedLength = 0;
    
    while (start < name.length()) {
        size_t dot = name.find('.', start);
        if (dot == std::string::npos) {
            dot = name.length();
        }
        
        size_t len = dot - start;
        if (len > 63) {
            throw std::runtime_error("Label too long: exceeds 63 bytes per label");
        }
        
        if (len == 0) {
            // Skip empty labels (double dots)
            start = dot + 1;
            continue;
        }
        
        // Check total encoded length
        encodedLength += len + 1; // +1 for length byte
        if (encodedLength > MAX_NAME_LENGTH) {
            throw std::runtime_error("Encoded domain name too long: exceeds 255 bytes");
        }
        
        buffer.push_back(static_cast<uint8_t>(len));
        buffer.insert(buffer.end(), name.begin() + start, name.begin() + dot);
        start = dot + 1;
    }
    
    buffer.push_back(0); // Null terminator
}

std::vector<uint8_t> DnsPacket::encodeRecordData(DnsType type, const std::string& data) {
    std::vector<uint8_t> result;
    
    switch (type) {
        case DnsType::A: {
            struct in_addr addr;
            if (inet_aton(data.c_str(), &addr) == 0) {
                throw std::runtime_error("Invalid IPv4 address: " + data);
            }
            // addr.s_addr is in network byte order, convert to host order for extraction
            uint32_t ip = ntohl(addr.s_addr);
            result.push_back((ip >> 24) & 0xFF);
            result.push_back((ip >> 16) & 0xFF);
            result.push_back((ip >> 8) & 0xFF);
            result.push_back(ip & 0xFF);
            break;
        }
        case DnsType::AAAA: {
            struct in6_addr addr6;
            if (inet_pton(AF_INET6, data.c_str(), &addr6) != 1) {
                throw std::runtime_error("Invalid IPv6 address: " + data);
            }
            for (int i = 0; i < 16; i++) {
                result.push_back(addr6.s6_addr[i]);
            }
            break;
        }
        case DnsType::CNAME:
        case DnsType::NS:
        case DnsType::PTR: {
            encodeName(result, data);
            break;
        }
        case DnsType::TXT: {
            result.push_back(static_cast<uint8_t>(data.length()));
            result.insert(result.end(), data.begin(), data.end());
            break;
        }
        case DnsType::MX: {
            // MX format: priority (2 bytes) + name
            size_t space = data.find(' ');
            if (space == std::string::npos) {
                throw std::runtime_error("Invalid MX record format");
            }
            uint16_t priority = static_cast<uint16_t>(std::stoi(data.substr(0, space)));
            writeUint16(result, priority);
            encodeName(result, data.substr(space + 1));
            break;
        }
        default:
            throw std::runtime_error("Unsupported record type for encoding");
    }
    
    return result;
}

std::string DnsPacket::decodeRecordData(DnsType type, const std::vector<uint8_t>& data, size_t offset, size_t length) {
    if (offset + length > data.size()) {
        throw std::runtime_error("Buffer overflow reading record data");
    }
    
    switch (type) {
        case DnsType::A: {
            if (length != 4) {
                throw std::runtime_error("Invalid A record length");
            }
            char ip[INET_ADDRSTRLEN];
            struct in_addr addr;
            addr.s_addr = htonl((data[offset] << 24) | (data[offset + 1] << 16) | 
                                (data[offset + 2] << 8) | data[offset + 3]);
            inet_ntop(AF_INET, &addr, ip, INET_ADDRSTRLEN);
            return std::string(ip);
        }
        case DnsType::AAAA: {
            if (length != 16) {
                throw std::runtime_error("Invalid AAAA record length");
            }
            char ip[INET6_ADDRSTRLEN];
            struct in6_addr addr6;
            std::memcpy(addr6.s6_addr, &data[offset], 16);
            inet_ntop(AF_INET6, &addr6, ip, INET6_ADDRSTRLEN);
            return std::string(ip);
        }
        case DnsType::CNAME:
        case DnsType::NS:
        case DnsType::PTR: {
            size_t nameOffset = offset;
            return decodeName(data, nameOffset);
        }
        case DnsType::TXT: {
            if (length == 0) return "";
            return std::string(reinterpret_cast<const char*>(&data[offset + 1]), data[offset]);
        }
        case DnsType::MX: {
            if (length < 3) {
                throw std::runtime_error("Invalid MX record length");
            }
            uint16_t priority = (data[offset] << 8) | data[offset + 1];
            size_t nameOffset = offset + 2;
            std::string name = decodeName(data, nameOffset);
            return std::to_string(priority) + " " + name;
        }
        default: {
            // Return hex representation for unknown types
            std::ostringstream oss;
            for (size_t i = 0; i < length; i++) {
                oss << std::hex << static_cast<int>(data[offset + i]);
            }
            return oss.str();
        }
    }
}

DnsMessage DnsPacket::decode(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < 12) {
        throw std::runtime_error("DNS packet too short");
    }
    
    DnsMessage msg;
    size_t offset = 0;
    
    // Header
    msg.id = readUint16(buffer, offset);
    msg.flags = readUint16(buffer, offset);
    uint16_t qdcount = readUint16(buffer, offset);
    uint16_t ancount = readUint16(buffer, offset);
    uint16_t nscount = readUint16(buffer, offset);
    uint16_t arcount = readUint16(buffer, offset);
    
    // Questions
    for (uint16_t i = 0; i < qdcount; i++) {
        DnsQuestion q;
        q.name = decodeName(buffer, offset);
        q.type = static_cast<DnsType>(readUint16(buffer, offset));
        q.class_ = static_cast<DnsClass>(readUint16(buffer, offset));
        msg.questions.push_back(q);
    }
    
    // Answers
    for (uint16_t i = 0; i < ancount; i++) {
        if (offset >= buffer.size()) {
            throw std::runtime_error("Buffer overflow: incomplete answer record");
        }
        DnsAnswer a;
        a.name = decodeName(buffer, offset);
        a.type = static_cast<DnsType>(readUint16(buffer, offset));
        a.class_ = static_cast<DnsClass>(readUint16(buffer, offset));
        a.ttl = readUint32(buffer, offset);
        uint16_t rdlength = readUint16(buffer, offset);
        
        // Validate record data length
        if (offset + rdlength > buffer.size()) {
            throw std::runtime_error("Buffer overflow: record data extends beyond buffer");
        }
        
        a.data = decodeRecordData(a.type, buffer, offset, rdlength);
        offset += rdlength;
        msg.answers.push_back(a);
    }
    
    // Authority (skip for now)
    for (uint16_t i = 0; i < nscount; i++) {
        if (offset >= buffer.size()) {
            throw std::runtime_error("Buffer overflow: incomplete authority record");
        }
        std::string name = decodeName(buffer, offset);
        DnsType type = static_cast<DnsType>(readUint16(buffer, offset));
        DnsClass class_ = static_cast<DnsClass>(readUint16(buffer, offset));
        uint32_t ttl = readUint32(buffer, offset);
        uint16_t rdlength = readUint16(buffer, offset);
        
        // Validate record data length
        if (offset + rdlength > buffer.size()) {
            throw std::runtime_error("Buffer overflow: authority record data extends beyond buffer");
        }
        
        offset += rdlength;
    }
    
    // Additional (skip for now)
    for (uint16_t i = 0; i < arcount; i++) {
        if (offset >= buffer.size()) {
            throw std::runtime_error("Buffer overflow: incomplete additional record");
        }
        std::string name = decodeName(buffer, offset);
        DnsType type = static_cast<DnsType>(readUint16(buffer, offset));
        DnsClass class_ = static_cast<DnsClass>(readUint16(buffer, offset));
        uint32_t ttl = readUint32(buffer, offset);
        uint16_t rdlength = readUint16(buffer, offset);
        
        // Validate record data length
        if (offset + rdlength > buffer.size()) {
            throw std::runtime_error("Buffer overflow: additional record data extends beyond buffer");
        }
        
        offset += rdlength;
    }
    
    return msg;
}

std::vector<uint8_t> DnsPacket::encode(const DnsMessage& message) {
    std::vector<uint8_t> buffer;
    
    // Header
    writeUint16(buffer, message.id);
    writeUint16(buffer, message.flags);
    writeUint16(buffer, static_cast<uint16_t>(message.questions.size()));
    writeUint16(buffer, static_cast<uint16_t>(message.answers.size()));
    writeUint16(buffer, static_cast<uint16_t>(message.authority.size()));
    writeUint16(buffer, static_cast<uint16_t>(message.additional.size()));
    
    // Questions
    for (const auto& q : message.questions) {
        encodeName(buffer, q.name);
        writeUint16(buffer, static_cast<uint16_t>(q.type));
        writeUint16(buffer, static_cast<uint16_t>(q.class_));
    }
    
    // Answers
    for (const auto& a : message.answers) {
        encodeName(buffer, a.name);
        writeUint16(buffer, static_cast<uint16_t>(a.type));
        writeUint16(buffer, static_cast<uint16_t>(a.class_));
        writeUint32(buffer, a.ttl);
        
        std::vector<uint8_t> rdata = encodeRecordData(a.type, a.data);
        writeUint16(buffer, static_cast<uint16_t>(rdata.size()));
        buffer.insert(buffer.end(), rdata.begin(), rdata.end());
    }
    
    // Authority
    for (const auto& a : message.authority) {
        encodeName(buffer, a.name);
        writeUint16(buffer, static_cast<uint16_t>(a.type));
        writeUint16(buffer, static_cast<uint16_t>(a.class_));
        writeUint32(buffer, a.ttl);
        
        std::vector<uint8_t> rdata = encodeRecordData(a.type, a.data);
        writeUint16(buffer, static_cast<uint16_t>(rdata.size()));
        buffer.insert(buffer.end(), rdata.begin(), rdata.end());
    }
    
    // Additional
    for (const auto& a : message.additional) {
        encodeName(buffer, a.name);
        writeUint16(buffer, static_cast<uint16_t>(a.type));
        writeUint16(buffer, static_cast<uint16_t>(a.class_));
        writeUint32(buffer, a.ttl);
        
        std::vector<uint8_t> rdata = encodeRecordData(a.type, a.data);
        writeUint16(buffer, static_cast<uint16_t>(rdata.size()));
        buffer.insert(buffer.end(), rdata.begin(), rdata.end());
    }
    
    return buffer;
}

