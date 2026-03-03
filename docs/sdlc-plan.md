## SDLC Plan — 5-Week Sprint

### Sprint 1 (Week 1): Foundation
**Goal**: Build the core components and get a working DNS proxy.

- [x] Project scaffold (CMake, directory structure, .gitignore)
- [x] DNS packet parser (RFC 1035 header + question section, compression pointers)
- [x] Blocklist loader with O(1) lookup and subdomain matching
- [x] LRU cache with TTL expiry
- [x] Upstream resolver (UDP forwarding to 8.8.8.8)
- [x] Logger (stdout + file, thread-safe)
- [x] Config file parser
- [x] DNS server (UDP socket, recvfrom loop, handle_query)
- [x] main.cpp wiring, signal handling
- [x] Unit tests for packet, blocklist, cache

**Definition of Done**: Server starts, blocks `ads.google.com`, forwards `github.com`, logs all queries. ✅

---

### Sprint 2 (Week 2): Stability
**Goal**: Handle edge cases, RFC compliance, multithreading, and integration tests.

- [x] Full RFC query-type support: AAAA (IPv6), MX, TXT, CNAME (build_blocked_response)
- [x] NXDOMAIN pass-through with short TTL caching (60 s) and dedicated log action
- [x] Malformed packet recovery — bounds checking, qd_count guard, catch-all exception handler
- [x] Thread pool (ThreadPool class, 4 worker threads by default)
- [x] Whitelist (allow-list) support — load_whitelist(), whitelist(), unwhitelist()
- [x] Integration tests (test_integration.cpp)
- [x] Thread pool tests (test_thread_pool.cpp)

**Definition of Done**: 0 crashes on random malformed packets; all 28 tests pass. ✅

---

### Sprint 3 (Week 3): Performance
**Goal**: Achieve target throughput and measure performance.

- [ ] Benchmark suite (qps, p50/p99 latency)
- [ ] Cache hit-rate logging
- [ ] Memory profiling

**Definition of Done**: 1000+ qps on a single core, < 50ms cached latency.

---

### Sprint 4 (Week 4): Features
**Goal**: Advanced filtering and observability.

- [ ] Wildcard domain matching (`*.ads.com`)
- [ ] Real-time statistics endpoint (UDP/TCP)
- [ ] Reload blocklist without restart (SIGHUP)

**Definition of Done**: Wildcard rules block subdomains; stats endpoint returns JSON.

---

### Sprint 5 (Week 5): Polish
**Goal**: Production-ready packaging and documentation.

- [ ] CLI flags (--port, --config, --verbose)
- [ ] Install script / systemd service file
- [ ] Full README with examples
- [ ] Docker image
- [ ] Final documentation review

**Definition of Done**: `sudo make install` works; systemd service starts on boot.
