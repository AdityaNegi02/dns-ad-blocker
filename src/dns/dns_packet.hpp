#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace dns {

// DNS header as defined in RFC 1035 Section 4.1.1
struct DNSHeader {
    uint16_t id;       // Transaction ID
    uint16_t flags;    // Flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
    uint16_t qd_count; // Number of questions
    uint16_t an_count; // Number of answer RRs
    uint16_t ns_count; // Number of authority RRs
    uint16_t ar_count; // Number of additional RRs
};

// A single DNS question entry
struct DNSQuestion {
    std::string qname;  // Fully-qualified domain name
    uint16_t qtype;     // Query type (1=A, 28=AAAA, etc.)
    uint16_t qclass;    // Query class (1=IN for Internet)
};

// Parsed DNS packet
struct DNSPacket {
    DNSHeader header;
    std::vector<DNSQuestion> questions;
    std::vector<uint8_t> raw_data; // Copy of the original bytes (used for forwarding)
};

// Parse raw UDP bytes into a DNSPacket struct
DNSPacket parse_packet(const uint8_t* data, size_t length);

// Extract the first question's domain name from a parsed packet
std::string extract_domain(const DNSPacket& packet);

// Build a DNS response that answers all questions with the given IPv4 address (e.g. "0.0.0.0")
std::vector<uint8_t> build_response(const DNSPacket& query, const std::string& ipv4_address);

// Parse a DNS domain name starting at `offset` in `data`, advancing `offset` past it.
// Handles RFC 1035 label encoding and compression pointers (0xC0 prefix).
std::string parse_domain_name(const uint8_t* data, size_t length, size_t& offset);

// Encode a domain name string into DNS label format (length-prefixed labels + 0x00 terminator)
std::vector<uint8_t> encode_domain_name(const std::string& domain);

} // namespace dns
