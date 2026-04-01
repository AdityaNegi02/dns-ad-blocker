// tests/test_benchmark_utils.cpp
//
// Unit tests for Sprint 3 benchmark / performance utilities:
//   1. DNS query packet construction (build a raw A-record query, verify it parses correctly)
//   2. Percentile calculation with known data
//   3. format_bytes utility
//   4. get_rss_bytes returns a positive value on Linux

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <numeric>
#include <vector>

#include "dns/dns_packet.hpp"
#include "utils/memory_stats.hpp"

// ---------------------------------------------------------------------------
// Helper: build a minimal DNS A-record query packet for `domain`
// (same logic used by the benchmark tool)
// ---------------------------------------------------------------------------
static std::vector<uint8_t> build_benchmark_query(const std::string& domain,
                                                   uint16_t txid = 0xBEEF) {
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

    // Question section
    auto encoded = dns::encode_domain_name(domain);
    pkt.insert(pkt.end(), encoded.begin(), encoded.end());

    // QTYPE = A (1), QCLASS = IN (1)
    pkt.push_back(0x00); pkt.push_back(0x01);
    pkt.push_back(0x00); pkt.push_back(0x01);

    return pkt;
}

// ---------------------------------------------------------------------------
// Percentile helper (mirrors the benchmark tool implementation)
// ---------------------------------------------------------------------------
// NOLINTNEXTLINE(misc-unused-alias-decls)
[[maybe_unused]] static int64_t percentile(const std::vector<int64_t>& sorted, double pct) {
    if (sorted.empty()) return 0;
    size_t idx = static_cast<size_t>(pct / 100.0 * static_cast<double>(sorted.size() - 1) + 0.5);
    if (idx >= sorted.size()) idx = sorted.size() - 1;
    return sorted[idx];
}

// ---------------------------------------------------------------------------
// Test 1: DNS query packet construction
// Build a raw A-record query for "example.com" and verify it parses correctly.
// ---------------------------------------------------------------------------
static bool test_query_packet_construction() {
    const std::string domain = "example.com";
    const uint16_t    txid   = 0x1234;

    auto raw = build_benchmark_query(domain, txid);

    // Must be parseable
    dns::DNSPacket pkt = dns::parse_packet(raw.data(), raw.size());

    assert(pkt.header.id       == txid);
    assert(pkt.header.qd_count == 1);
    assert(pkt.header.an_count == 0);
    assert(pkt.questions.size() == 1);
    assert(pkt.questions[0].qname  == domain);
    assert(pkt.questions[0].qtype  == dns::QTYPE_A);
    assert(pkt.questions[0].qclass == 1); // IN

    // RD bit should be set (byte 2, bit 0 = 0x01)
    assert(raw[2] == 0x01);

    return true;
}

// ---------------------------------------------------------------------------
// Test 2: Percentile calculation with known data
// Input: {1,2,3,4,5,6,7,8,9,10}
// p50 = 5 or 6 (index 4 or 5 of 10), p90 = 9, p99 = 10
// ---------------------------------------------------------------------------
static bool test_percentile_calculation() {
    std::vector<int64_t> data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    // already sorted

    // p0 should be the minimum
    assert(percentile(data, 0)  == 1);

    // p100 should be the maximum
    assert(percentile(data, 100) == 10);

    // p50: index = round(0.5 * 9) = round(4.5) = 5 → value = 6
    assert(percentile(data, 50) == 6);

    // p90: index = round(0.9 * 9) = round(8.1) = 8 → value = 9
    assert(percentile(data, 90) == 9);

    // p99: index = round(0.99 * 9) = round(8.91) = 9 → value = 10
    assert(percentile(data, 99) == 10);

    // Single-element edge case
    std::vector<int64_t> single = {42};
    assert(percentile(single, 0)   == 42);
    assert(percentile(single, 50)  == 42);
    assert(percentile(single, 100) == 42);

    // Empty edge case
    std::vector<int64_t> empty;
    assert(percentile(empty, 50) == 0);

    return true;
}

// ---------------------------------------------------------------------------
// Test 3: format_bytes utility
// ---------------------------------------------------------------------------
static bool test_format_bytes() {
    // Exact boundary: 0 bytes
    assert(utils::format_bytes(0)    == "0 B");

    // Sub-KB
    assert(utils::format_bytes(512)  == "512 B");
    assert(utils::format_bytes(1023) == "1023 B");

    // Exactly 1 KB
    assert(utils::format_bytes(1024) == "1.0 KB");

    // ~12.5 KB
    assert(utils::format_bytes(12800) == "12.5 KB");

    // Exactly 1 MB
    assert(utils::format_bytes(1024 * 1024) == "1.0 MB");

    // ~3.2 MB
    assert(utils::format_bytes(3 * 1024 * 1024 + 200 * 1024) == "3.2 MB");

    // Exactly 1 GB
    assert(utils::format_bytes(static_cast<size_t>(1024) * 1024 * 1024) == "1.0 GB");

    return true;
}

// ---------------------------------------------------------------------------
// Test 4: get_rss_bytes returns a positive value on Linux
// On non-Linux builds this is allowed to return 0.
// ---------------------------------------------------------------------------
static bool test_get_rss_bytes() {
#ifdef __linux__
    size_t rss = utils::get_rss_bytes();
    // The process is running, so RSS must be > 0
    assert(rss > 0);
    (void)rss; // suppress unused-variable warning in some configurations
#endif
    // On non-Linux the function returns 0 — that is acceptable
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
        } catch (...) {
            std::cout << "  [FAIL] " << name << " — unknown exception\n";
        }
    };

    std::cout << "=== test_benchmark_utils ===\n";
    run("test_query_packet_construction", test_query_packet_construction);
    run("test_percentile_calculation",    test_percentile_calculation);
    run("test_format_bytes",              test_format_bytes);
    run("test_get_rss_bytes",             test_get_rss_bytes);

    std::cout << passed << "/" << total << " tests passed\n";
    return (passed == total) ? 0 : 1;
}
