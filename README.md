# 🛡️ DNS Ad Blocker — High-Performance Network Filter

• Developed a production-ready C++17 DNS ad blocker processing 4,000+ QPS with sub-1.5ms P99 latency using thread pools and POSIX UDP sockets.
• Optimized domain lookups via O(1) hash sets and a custom thread-safe LRU cache, reducing average query latency by 85% (300µs to 45µs).
• Engineered an RFC 1035 compliant DNS parser supporting compression pointers and multiple record types with real-time monitoring via a Stats API.
• **Tech Stack:** C++17, POSIX Sockets, Pthreads, CMake, LRU Cache, DNS Protocol (RFC 1035).

---

## ⚙️ How It Executes

The DNS Ad Blocker operates as a high-speed interceptor between your devices and the internet. Below is the detailed execution flow:

### 1. Initialization Phase
- **Configuration Loading:** The server reads `config/settings.conf` to set up the environment (listening port, upstream DNS provider like 8.8.8.8, and thread counts).
- **Blocklist Indexing:** Thousands of malicious domains are loaded from `config/blocklist.txt` into a `std::unordered_set`. This allows for **O(1) constant-time lookups**, ensuring that checking 100,000 domains takes the same time as checking one.
- **Thread Pool Bootstrapping:** A pool of worker threads is spawned immediately to handle incoming traffic, eliminating the 100-200µs overhead of creating a new thread for every query.

### 2. The Request Lifecycle
When a device on the network requests a domain (e.g., `google.com` or `ads.tracker.com`):
1. **Packet Reception:** The main listener thread receives the raw UDP packet on port 5353 and dispatches it to the next available worker thread.
2. **DNS Parsing:** The worker thread decodes the binary DNS header and extracts the query domain name, handling complex "Compression Pointers" to prevent memory-based pointer-cycle attacks.
3. **Filtering Logic:**
   - **Blocklist Check:** If the domain matches the blocklist (and isn't in the whitelist), the server constructs a "Sinkhole" response, pointing the domain to `0.0.0.0`.
   - **Cache Check:** If allowed, the server queries the **LRU Cache**. If the record is present, it returns the result in **<50µs**.
4. **Upstream Resolution:** If the cache misses, the query is forwarded to an upstream provider (e.g., Google/Cloudflare). The result is simultaneously sent back to the client and stored in the cache for future requests.

### 3. Concurrency & Performance
- **Locking Strategy:** Uses fine-grained `std::mutex` locks to protect the LRU cache, ensuring that multiple worker threads can read/write without corrupting memory.
- **Eviction Policy:** When the cache reaches its limit (e.g., 10,000 entries), it automatically evicts the **Least Recently Used** item, keeping memory usage constant and performance high.
- **Dynamic Reloading:** Supports `SIGHUP` signals to reload blocklists from disk without dropping active connections, allowing for "Live Updates."

---

## 🚀 Features

- 🚫 **Ad & Tracker Blocking:** Uses a high-performance hash set for O(1) domain lookup.
- ⚡ **High Performance:** Handles 1,000+ queries per second with sub-millisecond latency.
- 💾 **LRU Cache:** Thread-safe cache with O(1) access and eviction to minimize upstream latency.
- 🌐 **Multi-Query Support:** Handles A, AAAA, MX, TXT, and CNAME records.
- 🧵 **Thread Pool Architecture:** Distributes query processing across multiple worker threads.
- 📊 **Real-time Monitoring:** Built-in Web Dashboard and JSON API for live tracking.
- 🛡️ **Robustness:** Handles malformed packets and DNS compression pointers securely.

---

## 🛠️ Technical Stack & Topics

This project is a comprehensive application of **Systems Programming** and **Computer Networking**. Below is the map of technologies and concepts used:

### Libraries & Languages
- **Language:** C++17 (utilizing `std::mutex`, `std::atomic`, `std::unordered_map`, `std::list`).
- **Networking:** POSIX Sockets (`sys/socket.h`, `arpa/inet.h`) for raw UDP communication.
- **Concurrency:** Pthreads/C++ Threads for the thread pool implementation.
- **Build System:** CMake 3.16+ for cross-platform build orchestration.

### Key Computer Science Topics
- **Networking:** DNS Protocol (RFC 1035), UDP vs TCP, Network Byte Order (Big Endian vs Little Endian).
- **Data Structures:** LRU Cache (Hash Map + Doubly Linked List), Hash Sets for O(1) blocklist lookups.
- **Operating Systems:** Signal Handling (SIGINT/SIGHUP), Process Memory Management (RSS tracking via `/proc`), Thread Synchronization.
- **Security:** Input validation, bounds-checking for binary parsers, and prevention of DNS pointer-cycle attacks.

---

## 🌍 Real-World Applications

1.  **Network-Wide Privacy:** Install on a Raspberry Pi to block ads for every device (TVs, iPhones, IoT) without installing client-side software.
2.  **Parental Controls:** Use the blocklist to restrict access to malicious or inappropriate domain categories.
3.  **Enterprise Security:** Prevent "Call Home" requests from malware or ransomware by blocking known Command & Control (C2) domains.
4.  **Performance Optimization:** Use as a local DNS cache to speed up web browsing by reducing redundant upstream queries.

---

## 📖 Step-by-Step Guide for Consumers

If you want to use this ad blocker on your own network, follow these steps to turn a Raspberry Pi or old computer into a dedicated network filter.

### 1. Preparation
- **Device:** A device running Linux (Ubuntu, Debian, or Raspberry Pi OS).
- **Network:** Ensure the device is connected to your router via Ethernet for best performance.

### 2. Installation
Transfer this project folder to your device, open a terminal, and run:
```bash
chmod +x install.sh
./install.sh
```
The script will compile the project, move files to the correct system folders, and start the blocker as a background service.

### 3. Verification & Dashboard
Once installed, you can check that everything is running smoothly:
- **Status:** `sudo systemctl status dns-ad-blocker`
- **Web Dashboard:** Open your browser and go to `http://<device-ip>:8080`. You will see a real-time dashboard showing your network's query stats and block rate.

### 4. Configure Your Network
To start blocking ads for all your devices:
1.  Log into your **Router Settings**.
2.  Find the **DHCP/DNS** section.
3.  Set the **Primary DNS Server** to the IP address of your device running this software.
4.  Save and Restart your router.

---

## 🏗️ Architecture

```text
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

## 📈 Performance

### Running the Benchmark
Build the project, then run the dedicated benchmark tool:
```bash
cd build
./dns_benchmark --queries 10000 --threads 4
```

**Sample Results:**
- **Throughput:** ~4,000 queries per second.
- **P99 Latency:** < 1.5ms.
- **Cache Hit Rate:** Significant latency reduction (avg 45µs vs 300µs for upstream).

---

## 🔨 Build & Run

### Using WSL (Recommended for Windows)
1. `cd /mnt/c/path/to/project`
2. `mkdir build && cd build`
3. `cmake .. && make -j4`
4. `sudo ./dns-ad-blocker`

### Testing
```bash
dig @127.0.0.1 -p 5353 google.com        # Should be ALLOWED
dig @127.0.0.1 -p 5353 doubleclick.net   # Should be BLOCKED (returns 0.0.0.0)
```

---

## 🗺️ Roadmap
- [x] Multi-threaded Query Handling
- [x] LRU Cache with TTL support
- [x] Statistics REST API
- [x] Web-based Management Dashboard
- [ ] DNS-over-HTTPS (DoH) Upstream Support
