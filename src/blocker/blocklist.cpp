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
// compile_wildcard
// ---------------------------------------------------------------------------
std::regex Blocklist::compile_wildcard(const std::string& pattern) {
    std::string regex_str = "^";
    for (char c : pattern) {
        if (c == '*') {
            regex_str += ".*";
        } else if (c == '.') {
            regex_str += "\\.";
        } else {
            regex_str += c;
        }
    }
    regex_str += "$";
    return std::regex(regex_str, std::regex_constants::icase);
}

// ---------------------------------------------------------------------------
// load_domains (private static helper)
// ---------------------------------------------------------------------------
bool Blocklist::load_domains(const std::string& filepath,
                             std::unordered_set<std::string>& exact_target,
                             std::vector<std::regex>& wildcard_target) {
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

        if (line.find('*') != std::string::npos) {
            wildcard_target.push_back(compile_wildcard(line));
        } else {
            exact_target.insert(normalize(line));
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// clear
// ---------------------------------------------------------------------------
void Blocklist::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    blocked_domains_.clear();
    whitelisted_domains_.clear();
    blocked_wildcards_.clear();
    whitelisted_wildcards_.clear();
}

// ---------------------------------------------------------------------------
// load
// ---------------------------------------------------------------------------
bool Blocklist::load(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(mutex_);
    return load_domains(filepath, blocked_domains_, blocked_wildcards_);
}

// ---------------------------------------------------------------------------
// load_whitelist
// ---------------------------------------------------------------------------
bool Blocklist::load_whitelist(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(mutex_);
    return load_domains(filepath, whitelisted_domains_, whitelisted_wildcards_);
}

// ---------------------------------------------------------------------------
// is_blocked
// ---------------------------------------------------------------------------
bool Blocklist::is_blocked(const std::string& domain) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string check = normalize(domain);

    // Whitelist wildcards
    for (const auto& regex : whitelisted_wildcards_) {
        if (std::regex_match(check, regex)) {
            return false;
        }
    }

    // Whitelist exact/parent matching
    std::string temp_check = check;
    while (true) {
        if (whitelisted_domains_.count(temp_check)) {
            return false;
        }
        size_t dot_pos = temp_check.find('.');
        if (dot_pos == std::string::npos) break;
        temp_check = temp_check.substr(dot_pos + 1);
    }

    // Blocklist wildcards
    for (const auto& regex : blocked_wildcards_) {
        if (std::regex_match(check, regex)) {
            return true;
        }
    }

    // Blocklist exact/parent matching
    temp_check = check;
    while (true) {
        if (blocked_domains_.count(temp_check)) {
            return true;
        }
        size_t dot_pos = temp_check.find('.');
        if (dot_pos == std::string::npos) break;
        temp_check = temp_check.substr(dot_pos + 1);
    }

    return false;
}

// ---------------------------------------------------------------------------
// add / remove / whitelist / unwhitelist
// ---------------------------------------------------------------------------

void Blocklist::add(const std::string& domain) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (domain.find('*') != std::string::npos) {
        blocked_wildcards_.push_back(compile_wildcard(domain));
    } else {
        blocked_domains_.insert(normalize(domain));
    }
}

void Blocklist::remove(const std::string& domain) {
    std::lock_guard<std::mutex> lock(mutex_);
    // Dynamically removing wildcards is complex with regex matching,
    // so we only implement exact removal. In a real-world scenario,
    // wildcards should ideally be kept in a map with their original string.
    blocked_domains_.erase(normalize(domain));
}

void Blocklist::whitelist(const std::string& domain) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (domain.find('*') != std::string::npos) {
        whitelisted_wildcards_.push_back(compile_wildcard(domain));
    } else {
        whitelisted_domains_.insert(normalize(domain));
    }
}

void Blocklist::unwhitelist(const std::string& domain) {
    std::lock_guard<std::mutex> lock(mutex_);
    whitelisted_domains_.erase(normalize(domain));
}

size_t Blocklist::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return blocked_domains_.size() + blocked_wildcards_.size();
}

size_t Blocklist::whitelist_size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return whitelisted_domains_.size() + whitelisted_wildcards_.size();
}

// ---------------------------------------------------------------------------
// estimated_memory
// ---------------------------------------------------------------------------
size_t Blocklist::estimated_memory() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t total = 0;
    for (const auto& domain : blocked_domains_) {
        total += domain.size() + 64;
    }
    // Very rough estimate for std::regex size
    total += blocked_wildcards_.size() * 128;
    return total;
}
