# 🛡️ DNS Ad Blocker

Network-level DNS ad blocker written in C++. Blocks ads and trackers for every device on your network.

---

## Features

- 🚫 Blocks ads, trackers, and malicious domains at the DNS level
- ⚡ High-performance: handles 1000+ queries per second
- 💾 LRU cache for sub-millisecond cached responses
- 🌐 Network-wide: covers every device on your network
- 📋 Easy-to-edit blocklist (plain text, one domain per line)
- 📊 Per-query logging with stats (BLOCKED / ALLOWED / CACHED)
- 🔧 Configurable upstream DNS (defaults to Google 8.8.8.8)
- 🛡️ Thread-safe design with std::mutex
- ⚙️ INI-style config file support
- 🔔 Graceful shutdown via SIGINT / SIGTERM

---

## Architecture

```
Devices on your network
        │
        ▼
   Router / DHCP
   (DNS = this server)
        │
        ▼
  ┌─────────────────────────┐
  │      DNS Ad Blocker     │
  │                         │
  │  ┌─────────────────┐    │
  │  │   DNS Server    │    │
  │  │  (UDP :5353)    │    │
  │  └────────┬────────┘    │
  │           │             │
  │  ┌────────▼────────┐    │
  │  │  Blocklist      │    │
  │  │  (unordered_set)│    │
  │  └────────┬────────┘    │
  │           │             │
  │  ┌────────▼────────┐    │
  │  │   LRU Cache     │    │
  │  └────────┬────────┘    │
  │           │             │
  │  ┌────────▼────────┐    │
  │  │ Upstream Resolver│   │
  │  │  (8.8.8.8:53)   │    │
  │  └─────────────────┘    │
  └─────────────────────────┘
        │
        ▼
   Upstream DNS
   (Google / Cloudflare)
```

---

## How It Works

1. A device on your network sends a DNS query (e.g. `ads.google.com`).
2. The DNS Ad Blocker receives the UDP packet on port 5353.
3. The domain is looked up in the **blocklist**. If found, `0.0.0.0` is returned immediately.
4. Otherwise the **LRU cache** is checked. If a cached response exists and hasn't expired, it's returned.
5. If not cached, the query is **forwarded** to the upstream DNS server (default: `8.8.8.8`).
6. The upstream response is **cached** and sent back to the client.
7. Every query is **logged** with its action (BLOCKED / CACHED / ALLOWED).

---

## Build Instructions

```bash
# Clone the repository
git clone https://github.com/AdityaNegi02/dns-ad-blocker.git
cd dns-ad-blocker

# Create build directory and configure
mkdir build && cd build
cmake ..

# Build the project
make -j$(nproc)
```

---

## Usage

```bash
# Run with default config
sudo ./dns-ad-blocker

# Run with a custom config file
sudo ./dns-ad-blocker --config /path/to/settings.conf

# Run on a custom port (overrides config)
sudo ./dns-ad-blocker --port 5353

# Test with dig (replace 127.0.0.1 with server IP)
dig @127.0.0.1 -p 5353 example.com
dig @127.0.0.1 -p 5353 ads.google.com   # should return 0.0.0.0
```

---

## Configuration

Edit `config/settings.conf`:

```ini
# DNS Ad Blocker Configuration
port=5353
upstream_dns=8.8.8.8
upstream_port=53
blocklist_path=config/blocklist.txt
log_path=logs/dns.log
cache_size=10000
log_level=info
```

Edit `config/blocklist.txt` to add/remove domains (one per line, `#` for comments).

---

## Running Tests

```bash
cd build
./test_dns_packet
./test_blocklist
./test_lru_cache
```

---

## 5-Week Roadmap

| Week | Sprint | Goals |
|------|--------|-------|
| 1 | Foundation | DNS packet parsing, blocklist, LRU cache, logger, config, basic server |
| 2 | Stability | Full RFC 1035 support, CNAME handling, error resilience |
| 3 | Performance | Threading, benchmarks, cache tuning |
| 4 | Features | Custom rules, wildcard matching, statistics API |
| 5 | Polish | CLI interface, installer, documentation, packaging |

---

## Tech Stack

- **Language**: C++17
- **Build**: CMake 3.16+
- **Networking**: POSIX sockets (Linux/macOS)
- **Threading**: `std::mutex`, `std::atomic`
- **Data structures**: `std::unordered_set`, `std::list` (LRU), `std::unordered_map`
- **Testing**: Custom assert-based test suite (no external framework)
