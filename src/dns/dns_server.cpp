#include "dns/dns_server.hpp"
#include "dns/dns_packet.hpp"
#include "utils/memory_stats.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <vector>

DNSServer::DNSServer(uint16_t port, Blocklist& blocklist, LRUCache& cache,
                     UpstreamResolver& resolver, Logger& logger,
                     size_t thread_count, uint32_t stats_interval_secs)
    : port_(port),
      socket_fd_(-1),
      running_(false),
      blocklist_(blocklist),
      cache_(cache),
      resolver_(resolver),
      logger_(logger),
      thread_pool_(std::make_unique<ThreadPool>(thread_count)),
      stats_interval_secs_(stats_interval_secs) {}

// ---------------------------------------------------------------------------
// start
// ---------------------------------------------------------------------------
// Opens a UDP socket, binds to 0.0.0.0:port_, tunes socket buffers for
// throughput, and enters the receive loop.  Also launches the background
// stats reporter thread.
void DNSServer::start() {
    // Create UDP socket
    socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd_ < 0) {
        throw std::runtime_error("DNSServer: failed to create socket");
    }

    // Allow reuse of the port (useful after a quick restart)
    int opt = 1;
    setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // ---- Task 4: Performance tuning — increase socket buffer sizes ----
    // A 1 MB receive/send buffer reduces packet loss under burst traffic.
    int buf_size = 1024 * 1024; // 1 MB
    setsockopt(socket_fd_, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
    setsockopt(socket_fd_, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));

    // Bind to all interfaces on the configured port
    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port_);

    if (bind(socket_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(socket_fd_);
        throw std::runtime_error("DNSServer: failed to bind to port " + std::to_string(port_));
    }

    running_ = true;
    logger_.log_info("DNS server started on port " + std::to_string(port_));

    // Launch background stats reporter thread
    stats_thread_ = std::thread(&DNSServer::stats_loop, this);

    // ---- Task 4: Use 4096-byte buffer for EDNS0 support ----
    // Standard DNS uses 512 bytes; EDNS0 allows up to 4096.
    uint8_t buffer[4096];
    struct sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);

    while (running_) {
        ssize_t len = recvfrom(socket_fd_, buffer, sizeof(buffer), 0,
                               reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);
        if (len < 0) {
            if (!running_) break; // socket was closed by stop()
            logger_.log_warning("DNSServer: recvfrom error (errno=" + std::to_string(errno) + ")");
            continue;
        }

        // Copy buffer data for the thread (buffer will be reused by next recvfrom)
        auto query_data = std::make_shared<std::vector<uint8_t>>(buffer, buffer + len);
        auto client     = client_addr; // copy for lambda capture
        thread_pool_->submit([this, query_data, client]() {
            handle_query(query_data->data(), query_data->size(), client);
        });
    }
}

// ---------------------------------------------------------------------------
// stop
// ---------------------------------------------------------------------------
void DNSServer::stop() {
    running_ = false;

    // Wake the stats thread so it exits promptly instead of waiting out its
    // full sleep interval.
    stats_cv_.notify_all();

    if (socket_fd_ >= 0) {
        close(socket_fd_);
        socket_fd_ = -1;
    }

    // Join the stats thread before shutting down the thread pool
    if (stats_thread_.joinable()) {
        stats_thread_.join();
    }

    // Drain in-progress tasks before returning
    if (thread_pool_) {
        thread_pool_->shutdown();
    }
}

// ---------------------------------------------------------------------------
// handle_query
// ---------------------------------------------------------------------------
// Processes one DNS query packet:
//   1. Parse packet & extract domain
//   2. Check cache → serve if hit
//   3. Check blocklist → return 0.0.0.0 if blocked
//   4. Forward to upstream, cache result, send response
void DNSServer::handle_query(const uint8_t* buffer, size_t length,
                              const struct sockaddr_in& client_addr) {
    // Convert client IP to string for logging
    char client_ip_buf[INET_ADDRSTRLEN] = "unknown";
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip_buf, sizeof(client_ip_buf));
    std::string client_ip = client_ip_buf;

    try {
        // Parse the incoming DNS packet
        dns::DNSPacket query = dns::parse_packet(buffer, length);
        std::string domain   = dns::extract_domain(query);

        if (domain.empty()) {
            logger_.log_warning("Received query with no domain from " + client_ip);
            return;
        }

        ++total_queries_;

        // --- Step 1: Check LRU cache ---
        auto cached = cache_.get(domain);
        if (cached.has_value()) {
            // Copy the cached response and update the transaction ID to match this query.
            auto resp = cached.value(); // intentional copy
            if (resp.size() >= 2) {
                resp[0] = (query.header.id >> 8) & 0xFF;
                resp[1] = query.header.id & 0xFF;
            }
            sendto(socket_fd_, resp.data(), resp.size(), 0,
                   reinterpret_cast<const struct sockaddr*>(&client_addr), sizeof(client_addr));
            logger_.log_query(domain, "CACHED", client_ip);
            ++cached_queries_;
            return;
        }

        // --- Step 2: Check blocklist ---
        if (blocklist_.is_blocked(domain)) {
            auto blocked_resp = dns::build_blocked_response(query);
            sendto(socket_fd_, blocked_resp.data(), blocked_resp.size(), 0,
                   reinterpret_cast<const struct sockaddr*>(&client_addr), sizeof(client_addr));
            logger_.log_query(domain, "BLOCKED", client_ip);
            ++blocked_queries_;
            return;
        }

        // --- Step 3: Forward to upstream ---
        auto upstream_resp = resolver_.resolve(buffer, length);

        // Determine the RCODE in the upstream response for logging and TTL decisions
        uint8_t rcode = dns::get_rcode(upstream_resp);

        if (rcode == 2) {
            // SERVFAIL — do not cache; send the response back as-is
            if (upstream_resp.size() >= 2) {
                upstream_resp[0] = (query.header.id >> 8) & 0xFF;
                upstream_resp[1] = query.header.id & 0xFF;
            }
            sendto(socket_fd_, upstream_resp.data(), upstream_resp.size(), 0,
                   reinterpret_cast<const struct sockaddr*>(&client_addr), sizeof(client_addr));
            logger_.log_query(domain, "SERVFAIL", client_ip);
            ++servfail_queries_;
            return;
        }

        // Cache the original upstream response BEFORE modifying the transaction ID.
        // NXDOMAIN (RCODE=3) is cached with a shorter TTL.
        uint32_t cache_ttl = (rcode == 3) ? 60 : 300;
        cache_.put(domain, upstream_resp, cache_ttl);

        // Now update the transaction ID for the current client and send
        if (upstream_resp.size() >= 2) {
            upstream_resp[0] = (query.header.id >> 8) & 0xFF;
            upstream_resp[1] = query.header.id & 0xFF;
        }
        sendto(socket_fd_, upstream_resp.data(), upstream_resp.size(), 0,
               reinterpret_cast<const struct sockaddr*>(&client_addr), sizeof(client_addr));

        if (rcode == 3) {
            logger_.log_query(domain, "NXDOMAIN", client_ip);
            ++nxdomain_queries_;
        } else {
            logger_.log_query(domain, "ALLOWED", client_ip);
            ++allowed_queries_;
        }

    } catch (const std::exception& ex) {
        logger_.log_error("handle_query error from " + client_ip + ": " + ex.what());
    } catch (...) {
        logger_.log_error("handle_query unknown error from " + client_ip);
    }
}

// ---------------------------------------------------------------------------
// stats_loop
// ---------------------------------------------------------------------------
// Background thread: sleeps for stats_interval_secs_ seconds between each
// report.  Uses a condition variable so that stop() can wake it immediately
// for a clean, prompt shutdown.
//
// Each report includes:
//   - Per-query-type counts (total/blocked/allowed/cached/nxdomain/servfail)
//   - Cache size, hit rate, eviction count
//   - Memory usage: cache bytes, blocklist bytes, and process RSS
void DNSServer::stats_loop() {
    while (running_) {
        // Wait for the configured interval, or until stop() notifies us
        {
            std::unique_lock<std::mutex> lock(stats_cv_mutex_);
            stats_cv_.wait_for(lock, std::chrono::seconds(stats_interval_secs_),
                               [this] { return !running_.load(); });
        }

        if (!running_) break;

        // ---- Collect stats ----
        CacheStats  cs   = cache_.stats();
        QueryStats  qs   = logger_.get_stats();
        size_t      cache_size = cache_.size();

        // Cache hit rate: hits / (hits + misses) * 100, guarded against div-by-zero
        uint64_t total_lookups = cs.hits + cs.misses;
        double hit_rate = (total_lookups > 0)
                          ? static_cast<double>(cs.hits) / total_lookups * 100.0
                          : 0.0;

        // ---- Memory estimates ----
        size_t cache_mem     = cache_.estimated_memory();
        size_t blocklist_mem = blocklist_.estimated_memory();
        size_t rss_bytes     = utils::get_rss_bytes();

        // ---- Format and log the stats line ----
        std::ostringstream msg;
        msg << "total="     << qs.total_queries
            << " blocked="  << qs.blocked_count
            << " allowed="  << qs.allowed_count
            << " cached="   << qs.cached_count
            << " nxdomain=" << qs.nxdomain_count
            << " servfail=" << qs.servfail_count
            << " | cache: size=" << cache_size
            << std::fixed << std::setprecision(1)
            << " hit_rate=" << hit_rate << "%"
            << " evictions=" << cs.evictions
            << " | memory: cache=" << utils::format_bytes(cache_mem)
            << " blocklist=" << utils::format_bytes(blocklist_mem)
            << " rss=" << utils::format_bytes(rss_bytes);

        logger_.log_info("[STATS] " + msg.str());
    }
}
