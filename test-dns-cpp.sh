#!/bin/bash

# Test script for DNS server

echo "Testing DNS server at 127.0.0.1:53"
echo ""

echo "1. Testing example.local (should return 127.0.0.1 from overrides):"
python3 << 'EOF'
import socket
import struct

def dns_query(domain, server='127.0.0.1', port=53):
    # Create DNS query packet
    query_id = 0x1234
    flags = 0x0100  # Standard query
    questions = 1
    answers = 0
    authority = 0
    additional = 0
    
    # Build query
    packet = struct.pack('!HHHHHH', query_id, flags, questions, answers, authority, additional)
    
    # Add question: domain name + type (A=1) + class (IN=1)
    parts = domain.split('.')
    for part in parts:
        packet += struct.pack('!B', len(part)) + part.encode()
    packet += b'\x00'  # End of name
    packet += struct.pack('!HH', 1, 1)  # Type A, Class IN
    
    # Send query
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(packet, (server, port))
        response, addr = sock.recvfrom(512)
        sock.close()
        
        # Parse response (simplified - just get the IP)
        if len(response) > 12:
            # Skip header, find answer section
            offset = 12
            # Skip question
            for _ in range(len(parts) + 1):
                if offset >= len(response):
                    break
                length = response[offset]
                if length == 0:
                    offset += 1
                    break
                offset += length + 1
            offset += 4  # Skip type and class
            
            # Read TTL and data length
            if offset + 6 <= len(response):
                data_len = struct.unpack('!H', response[offset+4:offset+6])[0]
                if data_len == 4:  # IPv4 address
                    ip = socket.inet_ntoa(response[offset+6:offset+10])
                    return ip
        return "Failed to parse response"
    except Exception as e:
        return f"Error: {e}"

result = dns_query('example.local')
print(f"   Result: {result}")
EOF

echo ""
echo "2. Testing enable.control.dns.local:"
python3 -c "
import socket
import struct
domain = 'enable.control.dns.local'
parts = domain.split('.')
packet = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
for p in parts:
    packet += struct.pack('!B', len(p)) + p.encode()
packet += b'\x00\x00\x01\x00\x01'
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2)
sock.sendto(packet, ('127.0.0.1', 53))
resp, _ = sock.recvfrom(512)
sock.close()
if len(resp) > 30:
    ip = socket.inet_ntoa(resp[-4:])
    print(f'   Result: {ip} (overrides should now be enabled)')
"

echo ""
echo "3. Try using 'host' command instead of nslookup:"
echo "   host example.local 127.0.0.1"
echo ""
echo "Note: Use 127.0.0.1 (not 0.0.0.0) as the DNS server address"

