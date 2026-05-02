#include <cassert>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>

#include "blocker/blocklist.hpp"

// Helper: write a temporary blocklist file and return its path.
static std::string write_temp_blocklist(const std::string& contents) {
    std::string path = "test_blocklist_tmp.txt";
    std::ofstream f(path);
    f << contents;
    return path;
}

// ---------------------------------------------------------------------------
// Test 1: load() reads domains from file and returns the correct count
// ---------------------------------------------------------------------------
static bool test_load() {
    auto path = write_temp_blocklist(
        "# comment\n"
        "\n"
        "ads.google.com\n"
        "doubleclick.net\n"
        "  tracking.example.com  \n" // whitespace should be trimmed
    );
    Blocklist bl;
    assert(bl.load(path));
    assert(bl.size() == 3);
    return true;
}

// ---------------------------------------------------------------------------
// Test 2: a domain listed in the blocklist is blocked
// ---------------------------------------------------------------------------
static bool test_blocked() {
    auto path = write_temp_blocklist("ads.google.com\ndoubleclick.net\n");
    Blocklist bl;
    bl.load(path);
    assert(bl.is_blocked("ads.google.com"));
    assert(bl.is_blocked("doubleclick.net"));
    return true;
}

// ---------------------------------------------------------------------------
// Test 3: a domain NOT in the blocklist is allowed
// ---------------------------------------------------------------------------
static bool test_allowed() {
    auto path = write_temp_blocklist("ads.google.com\n");
    Blocklist bl;
    bl.load(path);
    assert(!bl.is_blocked("github.com"));
    assert(!bl.is_blocked("stackoverflow.com"));
    return true;
}

// ---------------------------------------------------------------------------
// Test 4: a subdomain of a blocked parent is also blocked
// ---------------------------------------------------------------------------
static bool test_subdomain() {
    auto path = write_temp_blocklist("doubleclick.net\n");
    Blocklist bl;
    bl.load(path);
    // "ad.doubleclick.net" should be blocked because "doubleclick.net" is blocked
    assert(bl.is_blocked("ad.doubleclick.net"));
    assert(bl.is_blocked("x.y.doubleclick.net"));
    return true;
}

// ---------------------------------------------------------------------------
// Test 5: matching is case-insensitive
// ---------------------------------------------------------------------------
static bool test_case_insensitive() {
    auto path = write_temp_blocklist("ads.google.com\n");
    Blocklist bl;
    bl.load(path);
    assert(bl.is_blocked("ADS.GOOGLE.COM"));
    assert(bl.is_blocked("Ads.Google.Com"));
    return true;
}

// ---------------------------------------------------------------------------
// Test 6: dynamic add() and remove()
// ---------------------------------------------------------------------------
static bool test_add_remove() {
    Blocklist bl;
    bl.add("tracker.example.com");
    assert(bl.size() == 1);
    assert(bl.is_blocked("tracker.example.com"));

    bl.remove("tracker.example.com");
    assert(bl.size() == 0);
    assert(!bl.is_blocked("tracker.example.com"));
    return true;
}

// ---------------------------------------------------------------------------
// Test 7: wildcard matching
// ---------------------------------------------------------------------------
static bool test_wildcard() {
    auto path = write_temp_blocklist(
        "*.tracker.com\n"
        "ads.*.net\n"
    );
    Blocklist bl;
    bl.load(path);
    assert(bl.is_blocked("a.tracker.com"));
    assert(bl.is_blocked("b.c.tracker.com"));
    assert(bl.is_blocked("ads.example.net"));
    assert(!bl.is_blocked("tracker.com")); // Because *.tracker.com implies something before .
    assert(!bl.is_blocked("ads.com"));
    return true;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    int passed = 0;
    int total  = 7;

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

    std::cout << "=== test_blocklist ===\n";
    run("test_load",             test_load);
    run("test_blocked",          test_blocked);
    run("test_allowed",          test_allowed);
    run("test_subdomain",        test_subdomain);
    run("test_case_insensitive", test_case_insensitive);
    run("test_add_remove",       test_add_remove);
    run("test_wildcard",         test_wildcard);

    std::cout << passed << "/" << total << " tests passed\n";
    return (passed == total) ? 0 : 1;
}
