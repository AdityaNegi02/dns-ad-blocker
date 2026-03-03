#include "config/config.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>

// ---------------------------------------------------------------------------
// Helper: trim whitespace from both ends of a string
// ---------------------------------------------------------------------------
static std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// ---------------------------------------------------------------------------
// load
// ---------------------------------------------------------------------------
// Parses key=value lines, skipping blank lines and # comments.
bool Config::load(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        // Trim the whole line first
        std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed[0] == '#') continue;

        // Split on the first '=' only
        size_t eq_pos = trimmed.find('=');
        if (eq_pos == std::string::npos) continue; // malformed line — skip

        std::string key   = trim(trimmed.substr(0, eq_pos));
        std::string value = trim(trimmed.substr(eq_pos + 1));

        if (!key.empty()) {
            settings_[key] = value;
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// get (private helper)
// ---------------------------------------------------------------------------
std::string Config::get(const std::string& key, const std::string& default_value) const {
    auto it = settings_.find(key);
    return (it != settings_.end()) ? it->second : default_value;
}

// ---------------------------------------------------------------------------
// Typed accessors
// ---------------------------------------------------------------------------

uint16_t Config::port() const {
    return static_cast<uint16_t>(std::stoul(get("port", "5353")));
}

std::string Config::upstream_dns() const {
    return get("upstream_dns", "8.8.8.8");
}

uint16_t Config::upstream_port() const {
    return static_cast<uint16_t>(std::stoul(get("upstream_port", "53")));
}

std::string Config::blocklist_path() const {
    return get("blocklist_path", "config/blocklist.txt");
}

std::string Config::log_path() const {
    return get("log_path", "logs/dns.log");
}

size_t Config::cache_size() const {
    return static_cast<size_t>(std::stoul(get("cache_size", "10000")));
}

std::string Config::log_level() const {
    return get("log_level", "info");
}
