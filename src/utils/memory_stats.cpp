#include "utils/memory_stats.hpp"

#include <fstream>
#include <sstream>
#include <iomanip>

namespace utils {

// ---------------------------------------------------------------------------
// get_rss_bytes
// ---------------------------------------------------------------------------
// Reads /proc/self/status and parses the "VmRSS:" line to obtain the
// Resident Set Size of this process.  Returns the value in bytes.
// Returns 0 on any parse failure or when running on a non-Linux system.
size_t get_rss_bytes() {
#ifdef __linux__
    std::ifstream status("/proc/self/status");
    if (!status.is_open()) {
        return 0;
    }

    std::string line;
    while (std::getline(status, line)) {
        // VmRSS line looks like: "VmRSS:    12345 kB"
        if (line.rfind("VmRSS:", 0) == 0) {
            std::istringstream ss(line.substr(6)); // skip "VmRSS:"
            size_t kb = 0;
            ss >> kb;
            return kb * 1024; // convert kibibytes → bytes
        }
    }
    return 0;
#else
    return 0;
#endif
}

// ---------------------------------------------------------------------------
// format_bytes
// ---------------------------------------------------------------------------
// Converts a raw byte count into a human-readable string.
// Uses 1024-based units and one decimal place for KB/MB/GB.
std::string format_bytes(size_t bytes) {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(1);

    if (bytes < 1024) {
        ss << bytes << " B";
    } else if (bytes < 1024 * 1024) {
        ss << static_cast<double>(bytes) / 1024.0 << " KB";
    } else if (bytes < static_cast<size_t>(1024) * 1024 * 1024) {
        ss << static_cast<double>(bytes) / (1024.0 * 1024.0) << " MB";
    } else {
        ss << static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0) << " GB";
    }

    return ss.str();
}

} // namespace utils
