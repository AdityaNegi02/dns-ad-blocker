#pragma once
#include <string>
#include <unordered_set>
#include <vector>
#include <regex>
#include <shared_mutex>
#include <mutex>

// Blocklist: stores a set of blocked domains and provides fast lookup.
// Supports exact match as well as parent-domain matching so that subdomains
// of a blocked domain are automatically blocked.
//
// A whitelist (allow-list) takes priority: any domain or parent domain in the
// whitelist is never blocked, regardless of the blocklist contents.
class Blocklist {
public:
    // Load domains from a plain-text file (one domain per line, # for comments).
    // Returns true on success, false if the file could not be opened.
    bool load(const std::string& filepath);

    // Load whitelist domains from a plain-text file (same format as blocklist).
    // Returns true on success, false if the file could not be opened.
    bool load_whitelist(const std::string& filepath);

    // Clears all existing domains.
    void clear();

    // Returns true if `domain` or any of its parent domains are in the blocklist
    // AND none of them are in the whitelist.
    // E.g. if "doubleclick.net" is blocked, "ad.doubleclick.net" is also blocked.
    bool is_blocked(const std::string& domain) const;

    // Dynamically add a domain to the blocklist (runtime modification)
    void add(const std::string& domain);

    // Dynamically remove a domain from the blocklist (runtime modification)
    void remove(const std::string& domain);

    // Dynamically add a domain to the whitelist (runtime modification)
    void whitelist(const std::string& domain);

    // Dynamically remove a domain from the whitelist (runtime modification)
    void unwhitelist(const std::string& domain);

    // Returns the number of entries in the blocklist
    size_t size() const;

    // Returns the number of entries in the whitelist
    size_t whitelist_size() const;

    // Estimate the number of bytes used by the blocklist's internal storage.
    // Approximation: sum of all stored domain strings + 64 bytes of overhead
    // per entry (unordered_set node, hash bucket pointer).
    size_t estimated_memory() const;

private:
    std::unordered_set<std::string> blocked_domains_;
    std::unordered_set<std::string> whitelisted_domains_;
    
    std::vector<std::regex> blocked_wildcards_;
    std::vector<std::regex> whitelisted_wildcards_;
    
    mutable std::mutex mutex_; // Protects concurrent access

    // Convert domain to lowercase for case-insensitive matching
    static std::string normalize(const std::string& domain);

    // Compile a wildcard string into a std::regex
    static std::regex compile_wildcard(const std::string& pattern);

    // Load domains from a file into a given set (shared logic for load/load_whitelist)
    static bool load_domains(const std::string& filepath,
                             std::unordered_set<std::string>& exact_target,
                             std::vector<std::regex>& wildcard_target);
};
