#pragma once
#include <atomic>
#include <cstdint>
#include <memory>
#include <netinet/in.h>
#include "dns/dns_packet.hpp"
#include "blocker/blocklist.hpp"
#include "cache/lru_cache.hpp"
#include "resolver/upstream_resolver.hpp"
#include "logger/logger.hpp"
#include "thread_pool/thread_pool.hpp"

// DNSServer listens on a UDP port, receives DNS queries, and:
//  1. Checks the LRU cache — serves cached responses immediately.
//  2. Checks the blocklist — returns appropriate blocked response for blocked domains.
//  3. Forwards other queries to the upstream resolver and caches the reply.
//  4. Dispatches each query to a ThreadPool for concurrent processing.
class DNSServer {
public:
    DNSServer(uint16_t port, Blocklist& blocklist, LRUCache& cache,
              UpstreamResolver& resolver, Logger& logger,
              size_t thread_count = 4);

    // Start the server loop (blocking — runs until stop() is called)
    void start();

    // Signal the server to stop (safe to call from a signal handler)
    void stop();

private:
    // Process a single incoming DNS query and send a response
    void handle_query(const uint8_t* buffer, size_t length,
                      const struct sockaddr_in& client_addr);

    uint16_t          port_;
    int               socket_fd_;
    std::atomic<bool> running_;

    Blocklist&        blocklist_;
    LRUCache&         cache_;
    UpstreamResolver& resolver_;
    Logger&           logger_;

    std::unique_ptr<ThreadPool> thread_pool_; // Concurrent query dispatching
};
