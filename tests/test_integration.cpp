// tests/test_integration.cpp
// Integration tests covering the full DNS ad-blocker pipeline.
//
// Tests:
//  1. Blocked A query → verify is_blocked() returns true
//  2. Allowed domain → verify is_blocked() returns false
//  3. AAAA query for blocked domain → verify 16-byte all-zero RDATA
//  4. Whitelist override → domain in blocklist AND whitelist → allowed
//  5. Cache put/get round-trip → response bytes match
//  6. Malformed packets → verify no crashes (empty, truncated, random bytes)

#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>
#include <random>

#include "blocker/blocklist.hpp"
#include "cache/lru_cache.hpp"
#include "dns/dns_packet.hpp"

// Helper: build a minimal DNS query packet for `domain` with the given qtype.
static std::vector<uint8_t> make_query(const std::string& domain,
                                       uint16_t qtype  = dns::QTYPE_A,
                                       uint16_t txid   = 0x1234) {
    std::vector<uint8_t> pkt;
    // Header
    pkt.push_back((txid >> 8) & 0xFF);
    pkt.push_back(txid & 0xFF);
    pkt.push_back(0x01); // flags hi: RD=1
    pkt.push_back(0x00); // flags lo
    pkt.push_back(0x00); pkt.push_back(0x01); // QDCOUNT = 1
    pkt.push_back(0x00); pkt.push_back(0x00); // ANCOUNT = 0
    pkt.push_back(0x00); pkt.push_back(0x00); // NSCOUNT = 0
    pkt.push_back(0x00); pkt.push_back(0x00); // ARCOUNT = 0
    auto encoded = dns::encode_domain_name(domain);
    pkt.insert(pkt.end(), encoded.begin(), encoded.end());
    pkt.push_back((qtype >> 8) & 0xFF);
    pkt.push_back(qtype & 0xFF);
    pkt.push_back(0x00); pkt.push_back(0x01); // QCLASS = IN
    return pkt;
}

// ---------------------------------------------------------------------------
// Test 1: Blocked domain is detected by is_blocked()
// ---------------------------------------------------------------------------
static bool test_blocked_domain() {
    Blocklist bl;
    bl.add("ads.google.com");
    assert(bl.is_blocked("ads.google.com"));

    // Also check subdomain blocking
    bl.add("doubleclick.net");
    assert(bl.is_blocked("sub.doubleclick.net"));

    // Allowed domain must not be blocked
    assert(!bl.is_blocked("github.com"));
    return true;
}

// ---------------------------------------------------------------------------
// Test 2: Allowed domain passes through
// ---------------------------------------------------------------------------
static bool test_allowed_domain() {
    Blocklist bl;
    bl.add("ads.google.com");
    bl.add("tracker.example.com");

    assert(!bl.is_blocked("github.com"));
    assert(!bl.is_blocked("stackoverflow.com"));
    assert(!bl.is_blocked("google.com")); // parent of ads.google.com but not blocked
    return true;
}

// ---------------------------------------------------------------------------
// Test 3: AAAA query for blocked domain returns all-zeros IPv6
// ---------------------------------------------------------------------------
static bool test_aaaa_blocked_response() {
    auto raw = make_query("ads.google.com", dns::QTYPE_AAAA, 0xABCD);
    dns::DNSPacket query = dns::parse_packet(raw.data(), raw.size());

    auto resp = dns::build_blocked_response(query);

    // Must be a valid response (at minimum header + question + answer)
    assert(resp.size() >= 12);

    // Transaction ID must match
    uint16_t resp_id = (static_cast<uint16_t>(resp[0]) << 8) | resp[1];
    assert(resp_id == 0xABCD);

    // QR bit must be set (response)
    assert(resp[2] & 0x80);

    // ANCOUNT must be 1
    uint16_t an_count = (static_cast<uint16_t>(resp[6]) << 8) | resp[7];
    assert(an_count == 1);

    // The last 16 bytes are the IPv6 RDATA — must be all zeros (::/128)
    assert(resp.size() >= 28);
    for (size_t i = resp.size() - 16; i < resp.size(); ++i) {
        assert(resp[i] == 0x00);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Test 4: Whitelist overrides blocklist
// ---------------------------------------------------------------------------
static bool test_whitelist_override() {
    Blocklist bl;
    bl.add("ads.google.com");
    assert(bl.is_blocked("ads.google.com")); // Blocked before whitelisting

    bl.whitelist("ads.google.com");
    assert(!bl.is_blocked("ads.google.com")); // Whitelist takes priority

    bl.unwhitelist("ads.google.com");
    assert(bl.is_blocked("ads.google.com")); // Blocked again after removing from whitelist
    return true;
}

// ---------------------------------------------------------------------------
// Test 5: Cache put/get round-trip
// ---------------------------------------------------------------------------
static bool test_cache_round_trip() {
    LRUCache cache(100);

    std::vector<uint8_t> fake_response = {0x00, 0x01, 0x80, 0x00, 0x00, 0x01,
                                          0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
    cache.put("example.com", fake_response, 300);

    auto result = cache.get("example.com");
    assert(result.has_value());
    assert(result.value() == fake_response);

    // Absent entry returns nullopt
    auto missing = cache.get("notcached.com");
    assert(!missing.has_value());
    return true;
}

// ---------------------------------------------------------------------------
// Test 6a: Empty packet → must not crash
// ---------------------------------------------------------------------------
static bool test_malformed_empty_packet() {
    try {
        dns::parse_packet(nullptr, 0);
        // Should have thrown
        return false;
    } catch (const std::exception&) {
        // Expected — exception is fine, crash is not
        return true;
    }
}

// ---------------------------------------------------------------------------
// Test 6b: Truncated packet → must not crash
// ---------------------------------------------------------------------------
static bool test_malformed_truncated_packet() {
    // 5 bytes — too short for a DNS header (requires 12)
    uint8_t buf[5] = {0x00, 0x01, 0x01, 0x00, 0x00};
    try {
        dns::parse_packet(buf, sizeof(buf));
        return false; // Should have thrown
    } catch (const std::exception&) {
        return true; // Expected
    }
}

// ---------------------------------------------------------------------------
// Test 6c: Random garbage bytes → must not crash
// ---------------------------------------------------------------------------
static bool test_malformed_random_bytes() {
    std::mt19937 rng(42);
    std::uniform_int_distribution<int> byte_dist(0, 255);
    std::uniform_int_distribution<int> len_dist(1, 512);

    for (int trial = 0; trial < 200; ++trial) {
        size_t len = static_cast<size_t>(len_dist(rng));
        std::vector<uint8_t> buf(len);
        for (auto& b : buf) b = static_cast<uint8_t>(byte_dist(rng));

        try {
            dns::parse_packet(buf.data(), buf.size());
            // Parsed without throwing — that is also fine
        } catch (const std::exception&) {
            // Exception is acceptable; a crash is not
        } catch (...) {
            // Unknown exception — still not a crash
        }
    }
    return true; // Reaching here means no crashes/aborts
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    int passed = 0;
    int total  = 8;

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
        } catch (...) {
            std::cout << "  [FAIL] " << name << " — unknown exception\n";
        }
    };

    std::cout << "=== test_integration ===\n";
    run("test_blocked_domain",           test_blocked_domain);
    run("test_allowed_domain",           test_allowed_domain);
    run("test_aaaa_blocked_response",    test_aaaa_blocked_response);
    run("test_whitelist_override",       test_whitelist_override);
    run("test_cache_round_trip",         test_cache_round_trip);
    run("test_malformed_empty_packet",   test_malformed_empty_packet);
    run("test_malformed_truncated_packet", test_malformed_truncated_packet);
    run("test_malformed_random_bytes",   test_malformed_random_bytes);

    std::cout << passed << "/" << total << " tests passed\n";
    return (passed == total) ? 0 : 1;
}
