// tools/benchmark.cpp
//
// Standalone DNS benchmark tool for the DNS Ad Blocker.
//
// Sends N DNS A-record queries to a target server using raw UDP sockets,
// measures wall-clock time and per-query latency, then prints a formatted
// report including throughput (qps) and latency percentiles (p50/p90/p95/p99).
//
// Usage:
//   ./dns_benchmark [--host 127.0.0.1] [--port 5353] [--queries 10000] [--threads 4]

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

// Pull in the DNS packet helpers from the main codebase
#include "dns/dns_packet.hpp"

// ---------------------------------------------------------------------------
// Domain lists used during benchmarking
// ---------------------------------------------------------------------------

// Domains that should be blocked by the ad blocker
static const std::vector<std::string> BLOCKED_DOMAINS = {
    "ads.google.com",
    "doubleclick.net",
    "ad.doubleclick.net",
    "googleadservices.com",
    "pagead2.googlesyndication.com",
    "adnxs.com",
    "ads.yahoo.com",
    "tracking.example.com",
};

// Domains that should be forwarded to upstream (not blocked)
static const std::vector<std::string> ALLOWED_DOMAINS = {
    "github.com",
    "google.com",
    "stackoverflow.com",
    "example.com",
    "wikipedia.org",
    "cloudflare.com",
    "mozilla.org",
    "openssl.org",
};

// Domains we query twice to warm the cache for "cached" scenario tests
static const std::vector<std::string> CACHED_DOMAINS = {
    "cached1.example.com",
    "cached2.example.com",
    "cached3.example.com",
    "cached4.example.com",
    "cached5.example.com",
    "cached6.example.com",
    "cached7.example.com",
    "cached8.example.com",
};

// ---------------------------------------------------------------------------
// build_query
// ---------------------------------------------------------------------------
// Constructs a minimal DNS A-record query packet for `domain`.
// Uses dns::encode_domain_name from the main codebase.
static std::vector<uint8_t> build_query(const std::string& domain, uint16_t txid) {
    std::vector<uint8_t> pkt;

    // Header (12 bytes)
    pkt.push_back((txid >> 8) & 0xFF);
    pkt.push_back(txid & 0xFF);
    pkt.push_back(0x01); // flags high: RD=1
    pkt.push_back(0x00); // flags low
    pkt.push_back(0x00); pkt.push_back(0x01); // QDCOUNT = 1
    pkt.push_back(0x00); pkt.push_back(0x00); // ANCOUNT = 0
    pkt.push_back(0x00); pkt.push_back(0x00); // NSCOUNT = 0
    pkt.push_back(0x00); pkt.push_back(0x00); // ARCOUNT = 0

    // Question section: encoded domain name
    auto encoded = dns::encode_domain_name(domain);
    pkt.insert(pkt.end(), encoded.begin(), encoded.end());

    // QTYPE = A (1), QCLASS = IN (1)
    pkt.push_back(0x00); pkt.push_back(0x01);
    pkt.push_back(0x00); pkt.push_back(0x01);

    return pkt;
}

// ---------------------------------------------------------------------------
// send_query
// ---------------------------------------------------------------------------
// Sends a DNS query to the target server and waits for a response.
// Returns the round-trip latency in microseconds, or -1 on error.
static int64_t send_query(int sock_fd,
                           const struct sockaddr_in& server_addr,
                           const std::string& domain,
                           uint16_t txid) {
    auto pkt = build_query(domain, txid);

    uint8_t response[4096];
    struct sockaddr_in from{};
    socklen_t from_len = sizeof(from);

    auto t0 = std::chrono::steady_clock::now();

    ssize_t sent = sendto(sock_fd, pkt.data(), pkt.size(), 0,
                          reinterpret_cast<const struct sockaddr*>(&server_addr),
                          sizeof(server_addr));
    if (sent < 0) return -1;

    ssize_t received = recvfrom(sock_fd, response, sizeof(response), 0,
                                reinterpret_cast<struct sockaddr*>(&from), &from_len);
    if (received < 0) return -1;

    auto t1 = std::chrono::steady_clock::now();
    return static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
}

// ---------------------------------------------------------------------------
// Benchmark scenario
// ---------------------------------------------------------------------------
struct ScenarioResult {
    std::string name;
    uint64_t    query_count;
    double      avg_us; // average latency in microseconds
};

// ---------------------------------------------------------------------------
// worker_thread
// ---------------------------------------------------------------------------
// Each worker thread gets a slice of `total_queries` to send.
// Latencies are collected into `latencies_out` (protected by `mtx`).
static void worker_thread(const std::string& host,
                           uint16_t port,
                           int queries_per_thread,
                           std::vector<int64_t>& latencies_out,
                           std::mutex& mtx,
                           std::atomic<uint64_t>& blocked_count,
                           std::atomic<uint64_t>& allowed_count,
                           std::atomic<uint64_t>& cached_count,
                           std::atomic<int64_t>&  blocked_us_total,
                           std::atomic<int64_t>&  allowed_us_total,
                           std::atomic<int64_t>&  cached_us_total) {
    // Create a per-thread UDP socket with a 5-second receive timeout
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    struct timeval tv{};
    tv.tv_sec  = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) != 1) {
        close(sock);
        return;
    }

    // Total domains per category
    size_t nb = BLOCKED_DOMAINS.size();
    size_t na = ALLOWED_DOMAINS.size();
    size_t nc = CACHED_DOMAINS.size();
    size_t ntotal = nb + na + nc;

    std::vector<int64_t> local_latencies;
    local_latencies.reserve(static_cast<size_t>(queries_per_thread));

    for (int i = 0; i < queries_per_thread; ++i) {
        // Round-robin across all domain categories
        size_t idx = static_cast<size_t>(i) % ntotal;
        std::string domain;
        int category; // 0=blocked, 1=allowed, 2=cached

        if (idx < nb) {
            domain   = BLOCKED_DOMAINS[idx % nb];
            category = 0;
        } else if (idx < nb + na) {
            domain   = ALLOWED_DOMAINS[(idx - nb) % na];
            category = 1;
        } else {
            domain   = CACHED_DOMAINS[(idx - nb - na) % nc];
            category = 2;
        }

        uint16_t txid = static_cast<uint16_t>(i & 0xFFFF);
        int64_t  lat  = send_query(sock, server_addr, domain, txid);

        if (lat >= 0) {
            local_latencies.push_back(lat);
            if (category == 0) {
                ++blocked_count;
                blocked_us_total.fetch_add(lat);
            } else if (category == 1) {
                ++allowed_count;
                allowed_us_total.fetch_add(lat);
            } else {
                ++cached_count;
                cached_us_total.fetch_add(lat);
            }
        }
    }

    close(sock);

    // Merge local results into the shared vector
    std::lock_guard<std::mutex> lock(mtx);
    latencies_out.insert(latencies_out.end(),
                         local_latencies.begin(), local_latencies.end());
}

// ---------------------------------------------------------------------------
// percentile
// ---------------------------------------------------------------------------
// Returns the value at the given percentile (0–100) of a sorted vector.
static int64_t percentile(const std::vector<int64_t>& sorted, double pct) {
    if (sorted.empty()) return 0;
    size_t idx = static_cast<size_t>(pct / 100.0 * static_cast<double>(sorted.size() - 1) + 0.5);
    if (idx >= sorted.size()) idx = sorted.size() - 1;
    return sorted[idx];
}

// ---------------------------------------------------------------------------
// print_usage
// ---------------------------------------------------------------------------
static void print_usage(const char* prog) {
    std::cout << "Usage: " << prog
              << " [--host <ip>] [--port <port>] [--queries <n>] [--threads <n>]\n"
              << "\n"
              << "  --host     Target server IP address  (default: 127.0.0.1)\n"
              << "  --port     Target server port        (default: 5353)\n"
              << "  --queries  Total number of queries   (default: 10000)\n"
              << "  --threads  Number of sender threads  (default: 4)\n"
              << "\n";
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    // ---- Parse command-line arguments ----
    std::string host    = "127.0.0.1";
    uint16_t    port    = 5353;
    int         queries = 10000;
    int         threads = 4;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "--host" || arg == "-h") && i + 1 < argc) {
            host = argv[++i];
        } else if ((arg == "--port" || arg == "-p") && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoul(argv[++i]));
        } else if ((arg == "--queries" || arg == "-q") && i + 1 < argc) {
            queries = std::stoi(argv[++i]);
        } else if ((arg == "--threads" || arg == "-t") && i + 1 < argc) {
            threads = std::stoi(argv[++i]);
        } else if (arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
    }

    if (queries <= 0 || threads <= 0) {
        std::cerr << "Error: --queries and --threads must be positive integers\n";
        return 1;
    }

    // ---- Shared state across worker threads ----
    std::vector<int64_t>    all_latencies;
    std::mutex              latencies_mutex;
    std::atomic<uint64_t>   blocked_count{0};
    std::atomic<uint64_t>   allowed_count{0};
    std::atomic<uint64_t>   cached_count{0};
    std::atomic<int64_t>    blocked_us_total{0};
    std::atomic<int64_t>    allowed_us_total{0};
    std::atomic<int64_t>    cached_us_total{0};

    // Distribute queries evenly across threads
    int queries_per_thread = queries / threads;
    int remainder          = queries % threads;

    // ---- Launch worker threads and time the run ----
    auto wall_start = std::chrono::steady_clock::now();

    std::vector<std::thread> worker_threads;
    worker_threads.reserve(static_cast<size_t>(threads));

    for (int t = 0; t < threads; ++t) {
        // Give the last thread any leftover queries
        int q = queries_per_thread + (t == threads - 1 ? remainder : 0);
        worker_threads.emplace_back(
            worker_thread,
            std::ref(host), port, q,
            std::ref(all_latencies), std::ref(latencies_mutex),
            std::ref(blocked_count), std::ref(allowed_count), std::ref(cached_count),
            std::ref(blocked_us_total), std::ref(allowed_us_total), std::ref(cached_us_total));
    }

    for (auto& t : worker_threads) {
        t.join();
    }

    auto wall_end = std::chrono::steady_clock::now();
    double elapsed_sec = std::chrono::duration<double>(wall_end - wall_start).count();

    // ---- Compute statistics ----
    std::sort(all_latencies.begin(), all_latencies.end());

    int64_t total_recorded = static_cast<int64_t>(all_latencies.size());
    double  qps            = (elapsed_sec > 0.0)
                             ? static_cast<double>(total_recorded) / elapsed_sec
                             : 0.0;

    // Compute per-category averages (guard against division by zero)
    auto avg_us = [](int64_t total, uint64_t count) -> double {
        return (count > 0) ? static_cast<double>(total) / static_cast<double>(count) : 0.0;
    };

    double blocked_avg = avg_us(blocked_us_total.load(), blocked_count.load());
    double allowed_avg = avg_us(allowed_us_total.load(), allowed_count.load());
    double cached_avg  = avg_us(cached_us_total.load(),  cached_count.load());

    // ---- Print report ----
    std::cout << "\n=== DNS Ad Blocker Benchmark ===\n"
              << "Target:     " << host << ":" << port << "\n"
              << "Queries:    " << queries << " requested, " << total_recorded << " completed\n"
              << "Threads:    " << threads << "\n"
              << std::fixed << std::setprecision(2)
              << "Duration:   " << elapsed_sec << " seconds\n"
              << "\n"
              << std::fixed << std::setprecision(0)
              << "Throughput: " << qps << " qps\n"
              << "\n";

    if (!all_latencies.empty()) {
        std::cout << "Latency (microseconds):\n"
                  << "  p50:  " << percentile(all_latencies, 50)  << "\n"
                  << "  p90:  " << percentile(all_latencies, 90)  << "\n"
                  << "  p95:  " << percentile(all_latencies, 95)  << "\n"
                  << "  p99:  " << percentile(all_latencies, 99)  << "\n"
                  << "  max:  " << all_latencies.back()           << "\n"
                  << "\n";
    }

    std::cout << "By type:\n"
              << std::fixed << std::setprecision(0)
              << "  Blocked domains: " << blocked_count << " queries, avg "
              << blocked_avg << " µs\n"
              << "  Allowed domains: " << allowed_count << " queries, avg "
              << allowed_avg << " µs\n"
              << "  Cached  domains: " << cached_count  << " queries, avg "
              << cached_avg  << " µs\n"
              << "\n";

    return 0;
}
