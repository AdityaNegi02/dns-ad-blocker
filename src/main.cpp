#include <csignal>
#include <cstring>
#include <iostream>
#include <string>

#include "config/config.hpp"
#include "blocker/blocklist.hpp"
#include "cache/lru_cache.hpp"
#include "resolver/upstream_resolver.hpp"
#include "logger/logger.hpp"
#include "dns/dns_server.hpp"

// Global server pointer so signal handlers can call stop()
static DNSServer* g_server = nullptr;
static Blocklist* g_blocklist = nullptr;
static Config* g_config = nullptr;

// SIGINT / SIGTERM handler — triggers graceful shutdown
static void signal_handler(int /*signum*/) {
    if (g_server) {
        g_server->stop();
    }
}

// SIGHUP handler — reloads blocklist and whitelist dynamically
static void reload_handler(int /*signum*/) {
    if (g_blocklist && g_config) {
        std::cout << "\n[INFO] SIGHUP received. Reloading blocklist and whitelist...\n";
        g_blocklist->clear();
        g_blocklist->load(g_config->blocklist_path());
        g_blocklist->load_whitelist(g_config->whitelist_path());
        std::cout << "[INFO] Reload complete: " << g_blocklist->size() << " blocked, " 
                  << g_blocklist->whitelist_size() << " whitelisted domains.\n";
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    // --- ASCII art banner ---
    std::cout << R"(
  ____  _   _ ____       _       _   _   ____  _     ___   ____ _  _______ ____
 |  _ \| \ | / ___|     / \   __| | | | | __ )| |   / _ \ / ___| |/ / ____|  _ \
 | | | |  \| \___ \    / _ \ / _` | | | |  _ \| |  | | | | |   | ' /|  _| | |_) |
 | |_| | |\  |___) |  / ___ \ (_| | |_| | |_) | |__| |_| | |___| . \| |___|  _ <
 |____/|_| \_|____/  /_/   \_\__,_|\___/|____/|_____\___/ \____|_|\_\_____|_| \_\

)" << "\n";

    // --- Parse command-line arguments ---
    std::string config_path = "config/settings.conf";
    uint16_t    override_port = 0;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--config" && i + 1 < argc) {
            config_path = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            override_port = static_cast<uint16_t>(std::stoul(argv[++i]));
        }
    }

    // --- Load configuration ---
    Config config;
    if (!config.load(config_path)) {
        std::cerr << "[WARNING] Could not open config file: " << config_path
                  << " — using defaults\n";
    }

    uint16_t port         = (override_port != 0) ? override_port : config.port();
    std::string upstream  = config.upstream_dns();
    uint16_t up_port      = config.upstream_port();
    std::string bl_path   = config.blocklist_path();
    std::string log_path  = config.log_path();
    size_t cache_sz       = config.cache_size();
    size_t thread_count   = config.thread_count();
    std::string wl_path   = config.whitelist_path();
    uint32_t stats_interval = config.stats_interval();

    std::cout << "[INFO] Configuration loaded:\n"
              << "  port           = " << port         << "\n"
              << "  upstream_dns   = " << upstream     << "\n"
              << "  upstream_port  = " << up_port      << "\n"
              << "  blocklist_path = " << bl_path      << "\n"
              << "  log_path       = " << log_path     << "\n"
              << "  cache_size     = " << cache_sz     << "\n"
              << "  thread_count   = " << thread_count << "\n"
              << "  whitelist_path = " << wl_path      << "\n"
              << "  stats_interval = " << stats_interval << "s\n";

    // --- Load blocklist ---
    Blocklist blocklist;
    if (!blocklist.load(bl_path)) {
        std::cerr << "[WARNING] Could not load blocklist from: " << bl_path << "\n";
    }
    std::cout << "[INFO] Loaded " << blocklist.size() << " domains into blocklist\n";

    // --- Load whitelist ---
    if (!blocklist.load_whitelist(wl_path)) {
        std::cerr << "[WARNING] Could not load whitelist from: " << wl_path << " — continuing without whitelist\n";
    }
    std::cout << "[INFO] Loaded " << blocklist.whitelist_size() << " whitelisted domains\n";

    // --- Initialise components ---
    Logger           logger(log_path);
    LRUCache         cache(cache_sz);
    UpstreamResolver resolver(upstream, up_port);
    DNSServer        server(port, config.api_port(), blocklist, cache, resolver, logger, thread_count, stats_interval);

    // --- Register signal handlers ---
    g_server = &server;
    g_blocklist = &blocklist;
    g_config = &config;
    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);
#ifdef SIGHUP
    std::signal(SIGHUP, reload_handler);
#endif

    std::cout << "[INFO] Server listening on port " << port << " — press Ctrl+C to stop\n\n";

    // --- Run (blocking) ---
    try {
        server.start();
    } catch (const std::exception& ex) {
        std::cerr << "[ERROR] " << ex.what() << "\n";
        return 1;
    }

    std::cout << "\n[INFO] Server stopped. Goodbye!\n";
    return 0;
}
