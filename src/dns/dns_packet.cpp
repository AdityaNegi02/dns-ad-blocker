#include "dns/dns_packet.hpp"

#include <arpa/inet.h>   // ntohs, htons, inet_pton
#include <stdexcept>
#include <sstream>
#include <cstring>

namespace dns {

// ---------------------------------------------------------------------------
// parse_domain_name
// ---------------------------------------------------------------------------
// Reads a DNS domain name from `data` starting at `offset`.
// Handles both plain label encoding and compression pointers (RFC 1035 §4.1.4).
// After the call, `offset` points to the byte just after the name (or pointer).
std::string parse_domain_name(const uint8_t* data, size_t length, size_t& offset) {
    std::string domain;
    bool jumped = false;        // True if we followed a compression pointer
    size_t original_offset = 0; // Save offset after the pointer for correct advancement
    int iterations = 0;         // Guard against malicious pointer cycles (RFC 1035 §4.1.4)
    const int MAX_ITERATIONS = 256;

    while (offset < length) {
        if (++iterations > MAX_ITERATIONS) {
            throw std::runtime_error("DNS domain name exceeds maximum iterations (possible pointer cycle)");
        }

        uint8_t label_len = data[offset];

        if (label_len == 0) {
            // Null terminator — end of domain name
            if (!jumped) {
                ++offset; // advance past the 0x00 only if we didn't jump
            }
            break;
        }

        if ((label_len & 0xC0) == 0xC0) {
            // Compression pointer: next 14 bits are the offset into the packet
            if (offset + 1 >= length) {
                throw std::runtime_error("DNS compression pointer out of bounds");
            }
            uint16_t ptr = (static_cast<uint16_t>(label_len & 0x3F) << 8) | data[offset + 1];
            if (!jumped) {
                // Remember where the caller should continue after this pointer
                original_offset = offset + 2;
            }
            jumped = true;
            offset = ptr; // Follow the pointer
        } else {
            // Plain label: length byte followed by that many ASCII characters
            offset++;
            if (offset + label_len > length) {
                throw std::runtime_error("DNS label length exceeds packet bounds");
            }
            if (!domain.empty()) {
                domain += '.';
            }
            domain.append(reinterpret_cast<const char*>(data + offset), label_len);
            offset += label_len;
        }
    }

    if (jumped) {
        // Restore offset to byte after the compression pointer, not after the target
        offset = original_offset;
    }

    return domain;
}

// ---------------------------------------------------------------------------
// encode_domain_name
// ---------------------------------------------------------------------------
// Converts "www.google.com" → {3,'w','w','w', 6,'g','o','o','g','l','e', 3,'c','o','m', 0}
std::vector<uint8_t> encode_domain_name(const std::string& domain) {
    std::vector<uint8_t> result;
    std::istringstream ss(domain);
    std::string label;

    while (std::getline(ss, label, '.')) {
        if (label.empty()) continue;
        result.push_back(static_cast<uint8_t>(label.size()));
        for (char c : label) {
            result.push_back(static_cast<uint8_t>(c));
        }
    }
    result.push_back(0x00); // Root label terminator
    return result;
}

// ---------------------------------------------------------------------------
// parse_packet
// ---------------------------------------------------------------------------
// Parses the 12-byte DNS header and all question section entries.
DNSPacket parse_packet(const uint8_t* data, size_t length) {
    if (length < 12) {
        throw std::runtime_error("Packet too small to contain DNS header");
    }

    DNSPacket packet;

    // Store a copy of the raw bytes (needed for upstream forwarding)
    packet.raw_data.assign(data, data + length);

    // Parse the 12-byte header — all multi-byte fields are big-endian (network order).
    // Use memcpy to read uint16_t values to avoid undefined behaviour from unaligned access.
    auto read_u16 = [&](size_t off) -> uint16_t {
        uint16_t val;
        std::memcpy(&val, data + off, sizeof(val));
        return ntohs(val);
    };

    packet.header.id       = read_u16(0);
    packet.header.flags    = read_u16(2);
    packet.header.qd_count = read_u16(4);
    packet.header.an_count = read_u16(6);
    packet.header.ns_count = read_u16(8);
    packet.header.ar_count = read_u16(10);

    // Sanity-check qd_count to prevent pathological loops on malformed input
    if (packet.header.qd_count >= 100) {
        throw std::runtime_error("DNS qd_count unreasonably large");
    }

    // Parse question section (qd_count entries follow the header)
    size_t offset = 12;
    for (uint16_t i = 0; i < packet.header.qd_count; ++i) {
        DNSQuestion question;
        question.qname  = parse_domain_name(data, length, offset);

        if (offset + 4 > length) {
            throw std::runtime_error("Truncated DNS question section");
        }
        question.qtype  = read_u16(offset);
        question.qclass = read_u16(offset + 2);
        offset += 4;

        packet.questions.push_back(std::move(question));
    }

    return packet;
}

// ---------------------------------------------------------------------------
// extract_domain
// ---------------------------------------------------------------------------
// Returns the domain name from the first question, or empty string if none.
std::string extract_domain(const DNSPacket& packet) {
    if (packet.questions.empty()) {
        return "";
    }
    return packet.questions[0].qname;
}

// ---------------------------------------------------------------------------
// build_response
// ---------------------------------------------------------------------------
// Builds a minimal DNS response with a single A-record answer for the given IPv4.
// Uses a compression pointer (0xC00C) to reference the question name in the answer.
std::vector<uint8_t> build_response(const DNSPacket& query, const std::string& ipv4_address) {
    // Require at least one question to build a meaningful response
    if (query.questions.empty()) {
        throw std::runtime_error("build_response: query has no questions");
    }

    std::vector<uint8_t> response;

    // Helper: append a uint16_t in network byte order
    auto push_u16 = [&](uint16_t host_val) {
        uint16_t net_val = htons(host_val);
        uint8_t bytes[2];
        std::memcpy(bytes, &net_val, 2);
        response.push_back(bytes[0]);
        response.push_back(bytes[1]);
    };

    // Helper: append a uint32_t in network byte order
    auto push_u32 = [&](uint32_t host_val) {
        uint32_t net_val = htonl(host_val);
        uint8_t bytes[4];
        std::memcpy(bytes, &net_val, 4);
        for (int j = 0; j < 4; ++j) response.push_back(bytes[j]);
    };

    // --- Header (12 bytes) ---
    push_u16(query.header.id);       // Transaction ID
    push_u16(0x8180);                // Flags: QR=1, RD=1, RA=1
    push_u16(query.header.qd_count); // QDCOUNT
    push_u16(static_cast<uint16_t>(query.questions.size())); // ANCOUNT
    push_u16(0);                     // NSCOUNT
    push_u16(0);                     // ARCOUNT

    // --- Question section ---
    for (const auto& q : query.questions) {
        auto encoded = encode_domain_name(q.qname);
        response.insert(response.end(), encoded.begin(), encoded.end());
        push_u16(q.qtype);
        push_u16(q.qclass);
    }

    // --- Answer section ---
    for (size_t i = 0; i < query.questions.size(); ++i) {
        // NAME: compression pointer to offset 12
        response.push_back(0xC0);
        response.push_back(0x0C);

        push_u16(1);     // TYPE = A
        push_u16(1);     // CLASS = IN

        // TTL = 300 seconds (4 bytes, network order)
        push_u32(300);

        push_u16(4);     // RDLENGTH = 4 bytes

        // RDATA: IPv4 address
        struct in_addr addr{};
        if (inet_pton(AF_INET, ipv4_address.c_str(), &addr) != 1) {
            response.push_back(0x00);
            response.push_back(0x00);
            response.push_back(0x00);
            response.push_back(0x00);
        } else {
            uint32_t ip = addr.s_addr;
            response.push_back((ip >> 0) & 0xFF);
            response.push_back((ip >> 8) & 0xFF);
            response.push_back((ip >> 16) & 0xFF);
            response.push_back((ip >> 24) & 0xFF);
        }
    }

    return response;
}

// ---------------------------------------------------------------------------
// build_blocked_response
// ---------------------------------------------------------------------------
// Returns a blocked DNS response appropriate for the query type:
//   - QTYPE_A    → 0.0.0.0 (A record with all-zeros IPv4)
//   - QTYPE_AAAA → :: (AAAA record with all-zeros IPv6, 16 bytes)
//   - All other  → NXDOMAIN (flags=0x8183, ANCOUNT=0, just header+question)
std::vector<uint8_t> build_blocked_response(const DNSPacket& query) {
    if (query.questions.empty()) {
        throw std::runtime_error("build_blocked_response: query has no questions");
    }

    const uint16_t qtype = query.questions[0].qtype;

    if (qtype == QTYPE_A) {
        // Standard blocked A record: return 0.0.0.0
        return build_response(query, "0.0.0.0");
    }

    // Shared helpers for building the response
    std::vector<uint8_t> response;

    auto push_u16 = [&](uint16_t host_val) {
        uint16_t net_val = htons(host_val);
        uint8_t bytes[2];
        std::memcpy(bytes, &net_val, 2);
        response.push_back(bytes[0]);
        response.push_back(bytes[1]);
    };

    auto push_u32 = [&](uint32_t host_val) {
        uint32_t net_val = htonl(host_val);
        uint8_t bytes[4];
        std::memcpy(bytes, &net_val, 4);
        for (int j = 0; j < 4; ++j) response.push_back(bytes[j]);
    };

    if (qtype == QTYPE_AAAA) {
        // --- AAAA blocked response: return :: (all-zeros IPv6) ---
        // Header
        push_u16(query.header.id);       // Transaction ID
        push_u16(0x8180);                // Flags: QR=1, RD=1, RA=1, RCODE=0
        push_u16(static_cast<uint16_t>(query.questions.size())); // QDCOUNT
        push_u16(static_cast<uint16_t>(query.questions.size())); // ANCOUNT
        push_u16(0);                     // NSCOUNT
        push_u16(0);                     // ARCOUNT

        // Question section
        for (const auto& q : query.questions) {
            auto encoded = encode_domain_name(q.qname);
            response.insert(response.end(), encoded.begin(), encoded.end());
            push_u16(q.qtype);
            push_u16(q.qclass);
        }

        // Answer section: AAAA record with all-zeros IPv6 address
        for (size_t i = 0; i < query.questions.size(); ++i) {
            response.push_back(0xC0); // NAME: compression pointer to offset 12
            response.push_back(0x0C);
            push_u16(QTYPE_AAAA); // TYPE = AAAA (28)
            push_u16(1);           // CLASS = IN
            push_u32(300);         // TTL = 300 seconds
            push_u16(16);          // RDLENGTH = 16 bytes (IPv6)
            // RDATA: :: (all zeros, 16 bytes)
            for (int b = 0; b < 16; ++b) response.push_back(0x00);
        }

        return response;
    }

    // --- All other types (MX, TXT, CNAME, NS, SOA, …): return NXDOMAIN ---
    // Flags: 0x8183 = QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
    push_u16(query.header.id);       // Transaction ID
    push_u16(0x8183);                // Flags: QR + recursion + NXDOMAIN
    push_u16(static_cast<uint16_t>(query.questions.size())); // QDCOUNT
    push_u16(0);                     // ANCOUNT = 0
    push_u16(0);                     // NSCOUNT
    push_u16(0);                     // ARCOUNT

    // Question section (mirrored back to client per RFC 1035)
    for (const auto& q : query.questions) {
        auto encoded = encode_domain_name(q.qname);
        response.insert(response.end(), encoded.begin(), encoded.end());
        push_u16(q.qtype);
        push_u16(q.qclass);
    }

    return response;
}

// ---------------------------------------------------------------------------
// get_rcode
// ---------------------------------------------------------------------------
// Extracts the RCODE from raw DNS response bytes.
// The RCODE occupies the bottom 4 bits of byte 3 (the low byte of the flags field).
// Returns 0xFF if the buffer is too short to contain a DNS header.
uint8_t get_rcode(const std::vector<uint8_t>& response) {
    if (response.size() < 4) {
        return 0xFF; // Not a valid DNS packet
    }
    return response[3] & 0x0F;
}

} // namespace dns
