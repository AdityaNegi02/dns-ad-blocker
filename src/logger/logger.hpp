#pragma once
#include <cstdint>
#include <fstream>
#include <mutex>
#include <string>

// Aggregate query statistics for monitoring
struct QueryStats {
    uint64_t total_queries  = 0;
    uint64_t blocked_count  = 0;
    uint64_t allowed_count  = 0;
    uint64_t cached_count   = 0;
    uint64_t error_count    = 0;
    uint64_t nxdomain_count = 0; // Queries that returned NXDOMAIN from upstream
    uint64_t servfail_count = 0; // Queries that returned SERVFAIL from upstream
};

// Thread-safe logger. Writes formatted log lines to stdout and optionally to a file.
//
// Log format:
//   [YYYY-MM-DD HH:MM:SS] [LEVEL] message
class Logger {
public:
    // Construct the logger. If `log_filepath` is non-empty, also write to that file.
    explicit Logger(const std::string& log_filepath = "");

    ~Logger();

    // Log a DNS query event.
    // action should be one of: "BLOCKED", "ALLOWED", "CACHED", "ERROR"
    void log_query(const std::string& domain, const std::string& action,
                   const std::string& client_ip);

    void log_info(const std::string& message);
    void log_error(const std::string& message);
    void log_warning(const std::string& message);

    // Return a snapshot of query statistics
    QueryStats get_stats() const;

private:
    std::ofstream   log_file_;
    mutable std::mutex mutex_;
    QueryStats      stats_;

    // Returns the current time as "[YYYY-MM-DD HH:MM:SS]"
    std::string timestamp();

    // Write a formatted log line (locks mutex)
    void write(const std::string& level, const std::string& message);
};
