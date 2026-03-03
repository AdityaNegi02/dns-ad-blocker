## SDLC Plan — 5-Week Sprint

### Sprint 1 (Week 1): Foundation
**Goal**: Build the core components and get a working DNS proxy.

- [ ] Project scaffold (CMake, directory structure, .gitignore)
- [ ] DNS packet parser (RFC 1035 header + question section, compression pointers)
- [ ] Blocklist loader with O(1) lookup and subdomain matching
- [ ] LRU cache with TTL expiry
- [ ] Upstream resolver (UDP forwarding to 8.8.8.8)
- [ ] Logger (stdout + file, thread-safe)
- [ ] Config file parser
- [ ] DNS server (UDP socket, recvfrom loop, handle_query)
- [ ] main.cpp wiring, signal handling
- [ ] Unit tests for packet, blocklist, cache

**Definition of Done**: Server starts, blocks `ads.google.com`, forwards `github.com`, logs all queries.

---

### Sprint 2 (Week 2): Stability
**Goal**: Handle edge cases and improve RFC compliance.

- [ ] Full RFC 1035: multiple questions, AAAA records, MX, TXT
- [ ] CNAME chain handling
- [ ] Malformed packet recovery (fuzzing)
- [ ] NXDOMAIN pass-through
- [ ] Integration tests

**Definition of Done**: 0 crashes on 10,000 random malformed packets.

---

### Sprint 3 (Week 3): Performance
**Goal**: Achieve target throughput and measure performance.

- [ ] Thread pool for concurrent query handling
- [ ] Benchmark suite (qps, p50/p99 latency)
- [ ] Cache hit-rate logging
- [ ] Memory profiling

**Definition of Done**: 1000+ qps on a single core, < 50ms cached latency.

---

### Sprint 4 (Week 4): Features
**Goal**: Advanced filtering and observability.

- [ ] Wildcard domain matching (`*.ads.com`)
- [ ] Custom allow-list (whitelist)
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
