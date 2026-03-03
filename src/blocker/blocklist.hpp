#pragma once
#include <string>
#include <unordered_set>

// Blocklist: stores a set of blocked domains and provides fast lookup.
// Supports exact match as well as parent-domain matching so that subdomains
// of a blocked domain are automatically blocked.
class Blocklist {
public:
    // Load domains from a plain-text file (one domain per line, # for comments).
    // Returns true on success, false if the file could not be opened.
    bool load(const std::string& filepath);

    // Returns true if `domain` or any of its parent domains are in the blocklist.
    // E.g. if "doubleclick.net" is blocked, "ad.doubleclick.net" is also blocked.
    bool is_blocked(const std::string& domain) const;

    // Dynamically add a domain to the blocklist (runtime modification)
    void add(const std::string& domain);

    // Dynamically remove a domain from the blocklist (runtime modification)
    void remove(const std::string& domain);

    // Returns the number of entries in the blocklist
    size_t size() const;

private:
    std::unordered_set<std::string> blocked_domains_;

    // Convert domain to lowercase for case-insensitive matching
    static std::string normalize(const std::string& domain);
};
