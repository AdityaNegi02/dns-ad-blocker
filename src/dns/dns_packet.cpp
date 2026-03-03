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

    while (offset < length) {
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
    std::vector<uint8_t> response;

    // --- Header (12 bytes) ---
    // Transaction ID — must match the query
    uint16_t id_be = htons(query.header.id);
    response.push_back((id_be >> 8) & 0xFF);
    response.push_back(id_be & 0xFF);

    // Flags: QR=1 (response), Opcode=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0
    // 0x8180 = 1000 0001 1000 0000
    response.push_back(0x81);
    response.push_back(0x80);

    // QDCOUNT — same as the query
    uint16_t qd = htons(query.header.qd_count);
    response.push_back((qd >> 8) & 0xFF);
    response.push_back(qd & 0xFF);

    // ANCOUNT — one answer per question
    uint16_t an = htons(static_cast<uint16_t>(query.questions.size()));
    response.push_back((an >> 8) & 0xFF);
    response.push_back(an & 0xFF);

    // NSCOUNT = 0, ARCOUNT = 0
    response.push_back(0x00); response.push_back(0x00);
    response.push_back(0x00); response.push_back(0x00);

    // --- Question section (copied verbatim from query) ---
    for (const auto& q : query.questions) {
        auto encoded = encode_domain_name(q.qname);
        response.insert(response.end(), encoded.begin(), encoded.end());

        uint16_t qt = htons(q.qtype);
        response.push_back((qt >> 8) & 0xFF);
        response.push_back(qt & 0xFF);

        uint16_t qc = htons(q.qclass);
        response.push_back((qc >> 8) & 0xFF);
        response.push_back(qc & 0xFF);
    }

    // --- Answer section (one RR per question) ---
    for (size_t i = 0; i < query.questions.size(); ++i) {
        // NAME: compression pointer to offset 12 (start of question section)
        // 0xC0 0x0C means "pointer to byte 12"
        response.push_back(0xC0);
        response.push_back(0x0C);

        // TYPE = A (1)
        response.push_back(0x00);
        response.push_back(0x01);

        // CLASS = IN (1)
        response.push_back(0x00);
        response.push_back(0x01);

        // TTL = 300 seconds
        response.push_back(0x00);
        response.push_back(0x00);
        response.push_back(0x01);
        response.push_back(0x2C);

        // RDLENGTH = 4 bytes (IPv4)
        response.push_back(0x00);
        response.push_back(0x04);

        // RDATA: parse the dotted IPv4 string into 4 bytes
        struct in_addr addr{};
        if (inet_pton(AF_INET, ipv4_address.c_str(), &addr) != 1) {
            // Default to 0.0.0.0 on parse failure
            response.push_back(0x00);
            response.push_back(0x00);
            response.push_back(0x00);
            response.push_back(0x00);
        } else {
            uint32_t ip = addr.s_addr; // Already in network byte order from inet_pton
            response.push_back((ip >> 0) & 0xFF);
            response.push_back((ip >> 8) & 0xFF);
            response.push_back((ip >> 16) & 0xFF);
            response.push_back((ip >> 24) & 0xFF);
        }
    }

    return response;
}

} // namespace dns
