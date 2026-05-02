# 🛡️ DNS Ad Blocker

Network-level DNS ad blocker written in C++. Blocks ads and trackers for every device on your network.

---

## Features

- 🚫 Blocks ads, trackers, and malicious domains at the DNS level
- ⚡ High-performance: handles 1000+ queries per second
- 💾 LRU cache for sub-millisecond cached responses
- 🌐 Network-wide: covers every device on your network
- 📋 Easy-to-edit blocklist (plain text, one domain per line)
- 📊 Per-query logging with stats (BLOCKED / ALLOWED / CACHED / NXDOMAIN / SERVFAIL)
- 🔧 Configurable upstream DNS (defaults to Google 8.8.8.8)
- 🛡️ Thread-safe design with std::mutex
- ⚙️ INI-style config file support
- 🔔 Graceful shutdown via SIGINT / SIGTERM
- 🔀 Multi-query-type support: A, AAAA (IPv6), MX, TXT, CNAME — blocked domains return the correct response for each type
- 🧵 Thread pool for concurrent query handling (configurable worker count, default 4)
- ✅ Whitelist (allow-list) support — domains in the whitelist are never blocked, even if they appear in the blocklist
- 🛡️ Malformed packet recovery — bounds-checked parser with catch-all exception handler; the server never crashes on bad input

---

## Performance

### Running the Benchmark

Build the project (see [Build Instructions](#build-instructions)), then run:

```bash
cd build

# Default: 10,000 queries to 127.0.0.1:5353 with 4 threads
./dns_benchmark

# Custom target, query count, and concurrency
./dns_benchmark --host 127.0.0.1 --port 5353 --queries 10000 --threads 4
```

**Sample output:**

```
=== DNS Ad Blocker Benchmark ===
Target:     127.0.0.1:5353
Queries:    10000 requested, 10000 completed
Threads:    4
Duration:   2.45 seconds

Throughput: 4081 qps

Latency (microseconds):
  p50:  122
  p90:  245
  p95:  389
  p99:  1024
  max:  5123

By type:
  Blocked domains: 4167 queries, avg 95 µs
  Allowed domains: 4166 queries, avg 312 µs
  Cached  domains: 1667 queries, avg 45 µs
```

### Cache Hit-Rate Monitoring

The server prints a stats summary every 30 seconds (configurable via `stats_interval` in `settings.conf`):

```
[INFO] [STATS] total=150 blocked=45 allowed=80 cached=20 nxdomain=3 servfail=2 | cache: size=65 hit_rate=75.2% evictions=0 | memory: cache=13.0 KB blocklist=512 B rss=8.3 MB
```

### Memory Usage Estimates

The server estimates memory usage at each stats interval:

| Component  | Estimate Method |
|------------|----------------|
| Cache      | `domain.size() + response.size() + 64` bytes per entry |
| Blocklist  | `domain.size() + 64` bytes per entry |
| Process RSS | `/proc/self/status` (Linux only) |

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

 Here are the step-by-step commands to run it using WSL:

  Step 1: Open WSL
  Open your terminal (PowerShell) and enter your Ubuntu environment:
   1 wsl

  Step 2: Navigate to the project
  Once inside the WSL shell, navigate to the project folder (Windows drives are mounted under /mnt/):

   1 cd /mnt/c/Users/adity/OneDrive/Desktop/dns-ad-blocker

  Step 3: Build using CMake
  Now use the Linux build tools that are already installed in your WSL:

   1 mkdir -p build && cd build
   2 cmake ..
   3 make -j4

  Step 4: Run the server
  Run the compiled binary using sudo because it's a network service):
   1 sudo ./dns-ad-blocker
  You should see the ASCII banner and the "server started" message.

  Step 5: Test it
  While the server is running in the first terminal, open another terminal window and run:

   1 # Test a normal domain
   2 dig @127.0.0.1 -p 5353 google.com
   3
   4 # Test a blocked domain (e.g., from your blocklist.txt)
   5 dig @127.0.0.1 -p 5353 doubleclick.net

  Step 6: Check the Statistics API
  Open your browser on Windows and go to:
  http://localhost:8080/stats
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
thread_count=4
whitelist_path=config/whitelist.txt
```

Edit `config/blocklist.txt` to add/remove domains (one per line, `#` for comments).

Edit `config/whitelist.txt` to allow domains that should never be blocked.

---

## Running Tests

```bash
cd build
./test_dns_packet
./test_blocklist
./test_lru_cache
./test_integration
./test_thread_pool
./test_benchmark_utils
```

---

## 5-Week Roadmap

| Week | Sprint | Goals |
|------|--------|-------|
| 1 | Foundation ✅ | DNS packet parsing, blocklist, LRU cache, logger, config, basic server |
| 2 | Stability ✅ | Multi-query-type support (AAAA/MX/TXT/CNAME), NXDOMAIN pass-through, thread pool, whitelist, malformed packet recovery, integration tests |
| 3 | Performance ✅ | Benchmarks (qps/p99 latency), cache hit-rate logging, memory profiling, socket tuning |
| 4 | Features ✅ | Wildcard matching, statistics API, SIGHUP reload |
| 5 | Polish ✅ | CLI interface, installer, documentation, packaging |

---

## Tech Stack

- **Language**: C++17
- **Build**: CMake 3.16+
- **Networking**: POSIX sockets (Linux/macOS)
- **Threading**: `std::mutex`, `std::atomic`
- **Data structures**: `std::unordered_set`, `std::list` (LRU), `std::unordered_map`
- **Testing**: Custom assert-based test suite (no external framework)
