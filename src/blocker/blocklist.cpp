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
// load
// ---------------------------------------------------------------------------
// Reads the file line by line. Lines starting with '#' or that are empty
// (after whitespace trimming) are skipped. All other lines are added to the
// blocked set after normalization.
bool Blocklist::load(const std::string& filepath) {
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

        blocked_domains_.insert(normalize(line));
    }

    return true;
}

// ---------------------------------------------------------------------------
// is_blocked
// ---------------------------------------------------------------------------
// Checks if `domain` or any parent domain is blocked.
// E.g. "sub.ads.example.com" → checks "sub.ads.example.com", "ads.example.com",
//      "example.com", "com".
bool Blocklist::is_blocked(const std::string& domain) const {
    std::string check = normalize(domain);

    while (true) {
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

size_t Blocklist::size() const {
    return blocked_domains_.size();
}
