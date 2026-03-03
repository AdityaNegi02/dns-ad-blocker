#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>

// Config: loads an INI-style configuration file and exposes typed accessors
// with sensible defaults.
//
// File format:
//   # comment
//   key=value
//   key = value   (whitespace around '=' is trimmed)
class Config {
public:
    // Load the configuration file at `filepath`.
    // Returns true on success, false if the file could not be opened.
    bool load(const std::string& filepath);

    // Typed accessors with default values
    uint16_t    port()            const; // default: 5353
    std::string upstream_dns()    const; // default: "8.8.8.8"
    uint16_t    upstream_port()   const; // default: 53
    std::string blocklist_path()  const; // default: "config/blocklist.txt"
    std::string log_path()        const; // default: "logs/dns.log"
    size_t      cache_size()      const; // default: 10000
    std::string log_level()       const; // default: "info"
    size_t      thread_count()    const; // default: 4
    std::string whitelist_path()  const; // default: "config/whitelist.txt"

private:
    std::unordered_map<std::string, std::string> settings_;

    // Return value for `key`, or `default_value` if the key is not present
    std::string get(const std::string& key, const std::string& default_value) const;
};
