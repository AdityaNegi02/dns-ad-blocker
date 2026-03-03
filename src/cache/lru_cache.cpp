#include "cache/lru_cache.hpp"

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------
LRUCache::LRUCache(size_t max_size) : max_size_(max_size) {}

// ---------------------------------------------------------------------------
// get
// ---------------------------------------------------------------------------
// Returns cached bytes for `domain` if present and not expired.
// Moves the accessed entry to the front (most-recently-used position).
std::optional<std::vector<uint8_t>> LRUCache::get(const std::string& domain) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = lookup_.find(domain);
    if (it == lookup_.end()) {
        // Cache miss
        ++stats_.misses;
        return std::nullopt;
    }

    auto& entry = *(it->second);

    // Check TTL expiry
    if (std::chrono::steady_clock::now() > entry.expiry) {
        // Entry has expired — remove it
        entries_.erase(it->second);
        lookup_.erase(it);
        ++stats_.misses;
        return std::nullopt;
    }

    // Move to front (mark as most-recently-used)
    entries_.splice(entries_.begin(), entries_, it->second);

    ++stats_.hits;
    return entry.response;
}

// ---------------------------------------------------------------------------
// put
// ---------------------------------------------------------------------------
// Inserts or updates a cache entry. Evicts LRU entry if at capacity.
void LRUCache::put(const std::string& domain, const std::vector<uint8_t>& response,
                   uint32_t ttl_seconds) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto expiry = std::chrono::steady_clock::now() + std::chrono::seconds(ttl_seconds);

    auto it = lookup_.find(domain);
    if (it != lookup_.end()) {
        // Update existing entry and move to front
        it->second->response = response;
        it->second->expiry   = expiry;
        entries_.splice(entries_.begin(), entries_, it->second);
        return;
    }

    // Evict if needed before inserting
    if (entries_.size() >= max_size_) {
        evict();
    }

    // Insert at front
    entries_.push_front(CacheEntry{domain, response, expiry});
    lookup_[domain] = entries_.begin();
}

// ---------------------------------------------------------------------------
// evict
// ---------------------------------------------------------------------------
// Removes the least-recently-used entry (back of the list).
// Must be called with mutex_ already held.
void LRUCache::evict() {
    if (entries_.empty()) return;

    auto last = std::prev(entries_.end());
    lookup_.erase(last->domain);
    entries_.erase(last);
    ++stats_.evictions;
}

// ---------------------------------------------------------------------------
// clear / size / stats
// ---------------------------------------------------------------------------

void LRUCache::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
    lookup_.clear();
}

size_t LRUCache::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
}

CacheStats LRUCache::stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}
