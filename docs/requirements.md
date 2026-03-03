## Functional Requirements

1. **UDP Listener**: Listen on configurable UDP port (default 5353) for DNS queries.
2. **DNS Parsing (RFC 1035)**: Parse DNS query packets including header, question section, and domain name labels with compression pointer support.
3. **Blocklist Checking**: Maintain an in-memory set of blocked domains; check exact matches and parent domain matches.
4. **0.0.0.0 Blocking**: Return `0.0.0.0` (A record) for blocked domains instead of NXDOMAIN.
5. **Upstream Forwarding**: Forward non-blocked, non-cached queries to a configurable upstream DNS server.
6. **LRU Caching**: Cache DNS responses with TTL-based expiry; evict least-recently-used entries when at capacity.
7. **Logging**: Log every query with domain, action (BLOCKED/ALLOWED/CACHED), client IP, and timestamp.
8. **Config File Support**: Load settings from an INI-style configuration file.
9. **Graceful Shutdown**: Handle SIGINT and SIGTERM to shut down the server cleanly.

---

## Non-Functional Requirements

- **Throughput**: Handle 1000+ queries per second.
- **Latency**: Cached responses returned in < 50ms.
- **Scale**: Support 100,000+ domains in blocklist without degraded performance.
- **Thread Safety**: All shared data structures protected with `std::mutex`.
- **Portability**: Compile and run on Linux and macOS using POSIX sockets.
- **Reliability**: Recover from malformed packets without crashing.
