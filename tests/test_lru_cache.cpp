#include <cassert>
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

#include "cache/lru_cache.hpp"

// Helper: make a dummy response vector from a string
static std::vector<uint8_t> make_resp(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

// ---------------------------------------------------------------------------
// Test 1: put() then get() returns the same value
// ---------------------------------------------------------------------------
static bool test_put_get() {
    LRUCache cache(10);
    auto resp = make_resp("response_example_com");
    cache.put("example.com", resp, 300);

    auto result = cache.get("example.com");
    assert(result.has_value());
    assert(result.value() == resp);
    return true;
}

// ---------------------------------------------------------------------------
// Test 2: get() for an unknown key returns nullopt (cache miss)
// ---------------------------------------------------------------------------
static bool test_miss() {
    LRUCache cache(10);
    auto result = cache.get("nothere.com");
    assert(!result.has_value());
    return true;
}

// ---------------------------------------------------------------------------
// Test 3: LRU eviction — capacity=2, inserting 3 evicts the first entry
// ---------------------------------------------------------------------------
static bool test_eviction() {
    LRUCache cache(2);
    cache.put("a.com", make_resp("a"), 300);
    cache.put("b.com", make_resp("b"), 300);
    // Accessing "a.com" makes it MRU, so "b.com" becomes LRU
    cache.get("a.com");
    // Insert "c.com" — "b.com" (LRU) should be evicted
    cache.put("c.com", make_resp("c"), 300);

    assert(!cache.get("b.com").has_value()); // evicted
    assert(cache.get("a.com").has_value());  // still present
    assert(cache.get("c.com").has_value());  // just inserted
    assert(cache.stats().evictions == 1);
    return true;
}

// ---------------------------------------------------------------------------
// Test 4: TTL expiry — entry with TTL=1s expires after 2 seconds
// ---------------------------------------------------------------------------
static bool test_ttl_expiry() {
    LRUCache cache(10);
    cache.put("short.com", make_resp("data"), 1 /* 1 second TTL */);

    // Should be present immediately
    assert(cache.get("short.com").has_value());

    // Wait for TTL to expire
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Should now be expired (miss)
    assert(!cache.get("short.com").has_value());
    return true;
}

// ---------------------------------------------------------------------------
// Test 5: hit/miss statistics are counted correctly
// ---------------------------------------------------------------------------
static bool test_stats() {
    LRUCache cache(10);
    cache.put("hit.com", make_resp("h"), 300);

    cache.get("hit.com");  // hit
    cache.get("hit.com");  // hit
    cache.get("miss.com"); // miss

    assert(cache.stats().hits   == 2);
    assert(cache.stats().misses == 1);
    return true;
}

// ---------------------------------------------------------------------------
// Test 6: clear() removes all entries
// ---------------------------------------------------------------------------
static bool test_clear() {
    LRUCache cache(10);
    cache.put("a.com", make_resp("a"), 300);
    cache.put("b.com", make_resp("b"), 300);
    assert(cache.size() == 2);

    cache.clear();
    assert(cache.size() == 0);
    assert(!cache.get("a.com").has_value());
    return true;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    int passed = 0;
    int total  = 6;

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

    std::cout << "=== test_lru_cache ===\n";
    run("test_put_get",    test_put_get);
    run("test_miss",       test_miss);
    run("test_eviction",   test_eviction);
    run("test_ttl_expiry", test_ttl_expiry);
    run("test_stats",      test_stats);
    run("test_clear",      test_clear);

    std::cout << passed << "/" << total << " tests passed\n";
    return (passed == total) ? 0 : 1;
}
