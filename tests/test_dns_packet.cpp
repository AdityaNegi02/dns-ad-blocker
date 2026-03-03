#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>
#include <arpa/inet.h>

#include "dns/dns_packet.hpp"

// Helper: build a minimal DNS query for `domain` with type A, class IN.
// Returns raw bytes in the same format a real DNS client would send.
static std::vector<uint8_t> make_query(const std::string& domain,
                                       uint16_t txid = 0x1234) {
    std::vector<uint8_t> pkt;

    // Header
    pkt.push_back((txid >> 8) & 0xFF);
    pkt.push_back(txid & 0xFF);
    pkt.push_back(0x01); // flags high: RD=1
    pkt.push_back(0x00); // flags low
    pkt.push_back(0x00); pkt.push_back(0x01); // QDCOUNT = 1
    pkt.push_back(0x00); pkt.push_back(0x00); // ANCOUNT = 0
    pkt.push_back(0x00); pkt.push_back(0x00); // NSCOUNT = 0
    pkt.push_back(0x00); pkt.push_back(0x00); // ARCOUNT = 0

    // Question: encoded domain
    auto encoded = dns::encode_domain_name(domain);
    pkt.insert(pkt.end(), encoded.begin(), encoded.end());

    // QTYPE = A (1), QCLASS = IN (1)
    pkt.push_back(0x00); pkt.push_back(0x01);
    pkt.push_back(0x00); pkt.push_back(0x01);

    return pkt;
}

// ---------------------------------------------------------------------------
// Test 1: parse a simple A-record query for "example.com"
// ---------------------------------------------------------------------------
static bool test_parse_simple_query() {
    auto raw = make_query("example.com", 0xABCD);
    dns::DNSPacket pkt = dns::parse_packet(raw.data(), raw.size());

    assert(pkt.header.id == 0xABCD);
    assert(pkt.header.qd_count == 1);
    assert(pkt.header.an_count == 0);
    assert(pkt.questions.size() == 1);
    assert(pkt.questions[0].qname  == "example.com");
    assert(pkt.questions[0].qtype  == 1);
    assert(pkt.questions[0].qclass == 1);
    assert(pkt.raw_data == raw);
    return true;
}

// ---------------------------------------------------------------------------
// Test 2: extract_domain returns the first question's domain
// ---------------------------------------------------------------------------
static bool test_extract_domain() {
    auto raw = make_query("www.google.com", 0x0001);
    dns::DNSPacket pkt = dns::parse_packet(raw.data(), raw.size());
    assert(dns::extract_domain(pkt) == "www.google.com");
    return true;
}

// ---------------------------------------------------------------------------
// Test 3: build_response for 0.0.0.0 — verify TxID match and ANCOUNT=1
// ---------------------------------------------------------------------------
static bool test_build_blocked_response() {
    auto raw = make_query("ads.google.com", 0x5678);
    dns::DNSPacket query = dns::parse_packet(raw.data(), raw.size());

    auto resp = dns::build_response(query, "0.0.0.0");

    // Minimum size: 12 (header) + question + answer RR (at least 16 bytes)
    assert(resp.size() >= 28);

    // Transaction ID must match query (first 2 bytes, big-endian)
    assert(((static_cast<uint16_t>(resp[0]) << 8) | resp[1]) == 0x5678);

    // QR bit must be set (response)
    assert(resp[2] & 0x80);

    // ANCOUNT must be 1 (bytes 6–7, big-endian)
    assert(((static_cast<uint16_t>(resp[6]) << 8) | resp[7]) == 1);

    // The last 4 bytes of the answer RDATA must be 0.0.0.0
    assert(resp[resp.size() - 4] == 0x00);
    assert(resp[resp.size() - 3] == 0x00);
    assert(resp[resp.size() - 2] == 0x00);
    assert(resp[resp.size() - 1] == 0x00);

    return true;
}

// ---------------------------------------------------------------------------
// Test 4: encode_domain_name produces correct label-format bytes
// ---------------------------------------------------------------------------
static bool test_encode_domain_name() {
    auto encoded = dns::encode_domain_name("www.google.com");

    // Expected: {3,'w','w','w', 6,'g','o','o','g','l','e', 3,'c','o','m', 0}
    std::vector<uint8_t> expected = {
        3, 'w', 'w', 'w',
        6, 'g', 'o', 'o', 'g', 'l', 'e',
        3, 'c', 'o', 'm',
        0
    };
    assert(encoded == expected);
    return true;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    int passed = 0;
    int total  = 4;

    auto run = [&](const char* name, bool (*fn)()) {
        try {
            if (fn()) {
                std::cout << "  [PASS] " << name << "\n";
                ++passed;
            } else {
                std::cout << "  [FAIL] " << name << "\n";
            }
        } catch (const std::exception& ex) {
            std::cout << "  [FAIL] " << name << " — exception: " << ex.what() << "\n";
        }
    };

    std::cout << "=== test_dns_packet ===\n";
    run("test_parse_simple_query",    test_parse_simple_query);
    run("test_extract_domain",        test_extract_domain);
    run("test_build_blocked_response",test_build_blocked_response);
    run("test_encode_domain_name",    test_encode_domain_name);

    std::cout << passed << "/" << total << " tests passed\n";
    return (passed == total) ? 0 : 1;
}
