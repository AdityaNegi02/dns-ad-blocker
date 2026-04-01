#pragma once
#include <cstddef>
#include <string>

namespace utils {

// Estimate of memory used by the DNS ad blocker components
struct MemoryEstimate {
    size_t cache_bytes;     // Estimated cache memory
    size_t blocklist_bytes; // Estimated blocklist memory
    size_t total_bytes;     // Total estimated memory (cache + blocklist)
};

// Get the current process RSS (Resident Set Size) from /proc/self/status.
// Returns the value in bytes, or 0 if unavailable (non-Linux systems).
size_t get_rss_bytes();

// Format a byte count into a human-readable string with one decimal place.
// Examples: "512 B", "12.5 KB", "3.2 MB", "1.1 GB"
std::string format_bytes(size_t bytes);

} // namespace utils
