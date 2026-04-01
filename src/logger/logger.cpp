#include "logger/logger.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------

Logger::Logger(const std::string& log_filepath) {
    if (!log_filepath.empty()) {
        log_file_.open(log_filepath, std::ios::app);
        // Non-fatal: if the file can't be opened we still log to stdout
    }
}

Logger::~Logger() {
    if (log_file_.is_open()) {
        log_file_.close();
    }
}

// ---------------------------------------------------------------------------
// timestamp
// ---------------------------------------------------------------------------
// Returns the current local time formatted as "[YYYY-MM-DD HH:MM:SS]"
std::string Logger::timestamp() {
    auto now    = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::localtime(&time_t), "[%Y-%m-%d %H:%M:%S]");
    return ss.str();
}

// ---------------------------------------------------------------------------
// write
// ---------------------------------------------------------------------------
// Formats and emits a log line to stdout (always) and to the log file (if open).
// Called with mutex_ already held by public methods.
void Logger::write(const std::string& level, const std::string& message) {
    std::string line = timestamp() + " [" + level + "] " + message;
    std::cout << line << "\n";
    if (log_file_.is_open()) {
        log_file_ << line << "\n";
        log_file_.flush();
    }
}

// ---------------------------------------------------------------------------
// log_query
// ---------------------------------------------------------------------------
// Logs a query event and increments the appropriate statistics counter.
void Logger::log_query(const std::string& domain, const std::string& action,
                       const std::string& client_ip) {
    std::lock_guard<std::mutex> lock(mutex_);

    ++stats_.total_queries;

    if (action == "BLOCKED") {
        ++stats_.blocked_count;
    } else if (action == "ALLOWED") {
        ++stats_.allowed_count;
    } else if (action == "CACHED") {
        ++stats_.cached_count;
    } else if (action == "NXDOMAIN") {
        ++stats_.nxdomain_count;
    } else if (action == "SERVFAIL") {
        ++stats_.servfail_count;
    } else if (action == "ERROR") {
        ++stats_.error_count;
    }

    write("QUERY", domain + " | " + action + " | " + client_ip);
}

// ---------------------------------------------------------------------------
// log_info / log_error / log_warning
// ---------------------------------------------------------------------------

void Logger::log_info(const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    write("INFO", message);
}

void Logger::log_error(const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    ++stats_.error_count;
    write("ERROR", message);
}

void Logger::log_warning(const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    write("WARNING", message);
}

// ---------------------------------------------------------------------------
// get_stats
// ---------------------------------------------------------------------------
QueryStats Logger::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}
