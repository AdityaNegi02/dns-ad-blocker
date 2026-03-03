#include "blocker/blocklist.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

// ---------------------------------------------------------------------------
// normalize
// ---------------------------------------------------------------------------
// Converts a domain name to lowercase for case-insensitive comparisons.
std::string Blocklist::normalize(const std::string& domain) {
    std::string lower = domain;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return lower;
}

// ---------------------------------------------------------------------------
// load_domains (private static helper)
// ---------------------------------------------------------------------------
// Shared logic for reading domains from a plain-text file into a set.
bool Blocklist::load_domains(const std::string& filepath,
                             std::unordered_set<std::string>& target) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        // Trim leading whitespace
        size_t start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) continue; // blank line

        // Trim trailing whitespace
        size_t end = line.find_last_not_of(" \t\r\n");
        line = line.substr(start, end - start + 1);

        // Skip comment lines
        if (line.empty() || line[0] == '#') continue;

        target.insert(normalize(line));
    }

    return true;
}

// ---------------------------------------------------------------------------
// load
// ---------------------------------------------------------------------------
// Reads the file line by line. Lines starting with '#' or that are empty
// (after whitespace trimming) are skipped. All other lines are added to the
// blocked set after normalization.
bool Blocklist::load(const std::string& filepath) {
    return load_domains(filepath, blocked_domains_);
}

// ---------------------------------------------------------------------------
// load_whitelist
// ---------------------------------------------------------------------------
// Same format as the blocklist file. Domains loaded here will never be blocked.
bool Blocklist::load_whitelist(const std::string& filepath) {
    return load_domains(filepath, whitelisted_domains_);
}

// ---------------------------------------------------------------------------
// is_blocked
// ---------------------------------------------------------------------------
// Checks if `domain` or any parent domain is blocked and NOT whitelisted.
// Whitelist check is done first at every level — if any level matches the
// whitelist, the domain is considered allowed regardless of the blocklist.
// E.g. "sub.ads.example.com" → checks "sub.ads.example.com", "ads.example.com",
//      "example.com", "com".
bool Blocklist::is_blocked(const std::string& domain) const {
    std::string check = normalize(domain);

    while (true) {
        // Whitelist takes priority: if any level is whitelisted, allow it
        if (whitelisted_domains_.count(check)) {
            return false;
        }
        if (blocked_domains_.count(check)) {
            return true;
        }
        // Strip the leftmost label to check the parent domain
        size_t dot_pos = check.find('.');
        if (dot_pos == std::string::npos) {
            break; // No more parent domains to check
        }
        check = check.substr(dot_pos + 1);
    }

    return false;
}

// ---------------------------------------------------------------------------
// add / remove / size
// ---------------------------------------------------------------------------

void Blocklist::add(const std::string& domain) {
    blocked_domains_.insert(normalize(domain));
}

void Blocklist::remove(const std::string& domain) {
    blocked_domains_.erase(normalize(domain));
}

void Blocklist::whitelist(const std::string& domain) {
    whitelisted_domains_.insert(normalize(domain));
}

void Blocklist::unwhitelist(const std::string& domain) {
    whitelisted_domains_.erase(normalize(domain));
}

size_t Blocklist::size() const {
    return blocked_domains_.size();
}

size_t Blocklist::whitelist_size() const {
    return whitelisted_domains_.size();
}
