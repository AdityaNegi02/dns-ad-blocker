## Architecture Overview

### Modules

| Module | File(s) | Responsibility |
|--------|---------|----------------|
| DNS Server | `src/dns/dns_server.*` | UDP socket, receive/send loop, orchestrate query handling |
| DNS Packet | `src/dns/dns_packet.*` | Parse raw UDP bytes into structured DNS packets; build response packets |
| Blocklist | `src/blocker/blocklist.*` | Load domain blocklist from file; O(1) lookup with subdomain matching |
| LRU Cache | `src/cache/lru_cache.*` | TTL-aware LRU cache for DNS responses |
| Upstream Resolver | `src/resolver/upstream_resolver.*` | Forward queries to upstream DNS over UDP |
| Logger | `src/logger/logger.*` | Thread-safe logging to stdout and optional file |
| Config | `src/config/config.*` | Parse INI-style config file |
| Main | `src/main.cpp` | Entry point: wire up all components, handle signals |

---

### Data Flow

```
[Client UDP packet]
       │
       ▼
  dns_server.cpp :: handle_query()
       │
       ├── dns_packet.cpp :: parse_packet()
       │        └── returns DNSPacket struct
       │
       ├── dns_packet.cpp :: extract_domain()
       │        └── returns domain string
       │
       ├── lru_cache.cpp :: get(domain)
       │   ├── HIT  → send cached response → log CACHED → return
       │   └── MISS → continue
       │
       ├── blocklist.cpp :: is_blocked(domain)
       │   ├── YES → build_response(0.0.0.0) → send → log BLOCKED → return
       │   └── NO  → continue
       │
       ├── upstream_resolver.cpp :: resolve(raw query)
       │        └── forwards to 8.8.8.8:53, returns response bytes
       │
       ├── lru_cache.cpp :: put(domain, response, ttl)
       │
       └── send response → log ALLOWED
```

---

### Thread Safety Notes

- `LRUCache`: All public methods acquire `std::mutex` via `std::lock_guard`.
- `Logger`: All write operations acquire `std::mutex` via `std::lock_guard`.
- `Blocklist`: Read-only after `load()` — no locking needed for `is_blocked()`.
- `DNSServer::running_`: `std::atomic<bool>` for lock-free stop signal.
- Future work: Thread pool for concurrent query handling.
