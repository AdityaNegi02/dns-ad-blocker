#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace dns {

// ---------------------------------------------------------------------------
// Common DNS query type constants (RFC 1035 / RFC 3596)
// ---------------------------------------------------------------------------
constexpr uint16_t QTYPE_A     = 1;   // IPv4 address
constexpr uint16_t QTYPE_NS    = 2;   // Name server
constexpr uint16_t QTYPE_CNAME = 5;   // Canonical name
constexpr uint16_t QTYPE_SOA   = 6;   // Start of authority
constexpr uint16_t QTYPE_MX    = 15;  // Mail exchange
constexpr uint16_t QTYPE_TXT   = 16;  // Text record
constexpr uint16_t QTYPE_AAAA  = 28;  // IPv6 address

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

// Build a blocked response that handles the query type appropriately:
//   - QTYPE_A    → returns 0.0.0.0
//   - QTYPE_AAAA → returns :: (all-zeros IPv6)
//   - All other  → returns NXDOMAIN (RCODE=3), no answer section
std::vector<uint8_t> build_blocked_response(const DNSPacket& query);

// Extract the RCODE (bottom 4 bits of byte 3) from a raw DNS response.
// Returns 0xFF if the response is too short.
uint8_t get_rcode(const std::vector<uint8_t>& response);

// Parse a DNS domain name starting at `offset` in `data`, advancing `offset` past it.
// Handles RFC 1035 label encoding and compression pointers (0xC0 prefix).
std::string parse_domain_name(const uint8_t* data, size_t length, size_t& offset);

// Encode a domain name string into DNS label format (length-prefixed labels + 0x00 terminator)
std::vector<uint8_t> encode_domain_name(const std::string& domain);

} // namespace dns
