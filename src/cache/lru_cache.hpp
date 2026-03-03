#pragma once
#include <chrono>
#include <cstdint>
#include <list>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

// A single entry stored in the cache
struct CacheEntry {
    std::string domain;
    std::vector<uint8_t> response;
    std::chrono::steady_clock::time_point expiry; // When this entry expires
};

// Counters for cache performance monitoring
struct CacheStats {
    uint64_t hits      = 0; // Requests served from cache
    uint64_t misses    = 0; // Requests not found in cache
    uint64_t evictions = 0; // Entries removed due to capacity
};

// Thread-safe LRU (Least-Recently-Used) cache for DNS responses.
//
// Implementation uses:
//   - std::list<CacheEntry> for O(1) insert/remove at any position
//   - std::unordered_map<domain, list::iterator> for O(1) lookup
//
// The most-recently-used entry is at the front of the list; the
// least-recently-used is at the back (eviction candidate).
class LRUCache {
public:
    explicit LRUCache(size_t max_size);

    // Look up a cached response for `domain`.
    // Returns the response bytes if found and not expired; nullopt otherwise.
    std::optional<std::vector<uint8_t>> get(const std::string& domain);

    // Store a response for `domain` with the given TTL in seconds.
    // If `domain` already exists, the entry is updated and moved to the front.
    // If the cache is full, the least-recently-used entry is evicted first.
    void put(const std::string& domain, const std::vector<uint8_t>& response, uint32_t ttl_seconds);

    // Remove all entries from the cache
    void clear();

    // Current number of entries
    size_t size() const;

    // Return a snapshot of hit/miss/eviction counters
    CacheStats stats() const;

private:
    size_t max_size_;
    std::list<CacheEntry> entries_;                                    // MRU at front, LRU at back
    std::unordered_map<std::string, std::list<CacheEntry>::iterator> lookup_; // domain → iterator
    mutable std::mutex mutex_;
    CacheStats stats_;

    // Remove the least-recently-used entry (back of list)
    void evict();
};
