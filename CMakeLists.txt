cmake_minimum_required(VERSION 3.16)
project(dns-ad-blocker)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compiler flags
add_compile_options(-Wall -Wextra -Wpedantic)

# Collect all source files from src/
file(GLOB_RECURSE SOURCES "src/**/*.cpp" "src/*.cpp")

# Main executable
add_executable(dns-ad-blocker ${SOURCES})
target_include_directories(dns-ad-blocker PRIVATE src/)
target_link_libraries(dns-ad-blocker pthread)

# ---- Tests ----

# test_dns_packet
add_executable(test_dns_packet
    tests/test_dns_packet.cpp
    src/dns/dns_packet.cpp
)
target_include_directories(test_dns_packet PRIVATE src/)

# test_blocklist
add_executable(test_blocklist
    tests/test_blocklist.cpp
    src/blocker/blocklist.cpp
)
target_include_directories(test_blocklist PRIVATE src/)

# test_lru_cache
add_executable(test_lru_cache
    tests/test_lru_cache.cpp
    src/cache/lru_cache.cpp
)
target_include_directories(test_lru_cache PRIVATE src/)
target_link_libraries(test_lru_cache pthread)

# test_integration
add_executable(test_integration
    tests/test_integration.cpp
    src/dns/dns_packet.cpp
    src/blocker/blocklist.cpp
    src/cache/lru_cache.cpp
)
target_include_directories(test_integration PRIVATE src/)
target_link_libraries(test_integration pthread)

# test_thread_pool
add_executable(test_thread_pool
    tests/test_thread_pool.cpp
    src/thread_pool/thread_pool.cpp
)
target_include_directories(test_thread_pool PRIVATE src/)
target_link_libraries(test_thread_pool pthread)

# ---- Sprint 3: Benchmark tool ----

# dns_benchmark: standalone CLI tool for throughput and latency measurement
add_executable(dns_benchmark
    tools/benchmark.cpp
    src/dns/dns_packet.cpp
)
target_include_directories(dns_benchmark PRIVATE src/)
target_link_libraries(dns_benchmark pthread)

# ---- Sprint 3: Benchmark utility tests ----

# test_benchmark_utils: tests for query construction, percentiles, memory utils
add_executable(test_benchmark_utils
    tests/test_benchmark_utils.cpp
    src/dns/dns_packet.cpp
    src/utils/memory_stats.cpp
)
target_include_directories(test_benchmark_utils PRIVATE src/)
target_link_libraries(test_benchmark_utils pthread)

# ---- Installation and Packaging ----
install(TARGETS dns-ad-blocker DESTINATION bin)
install(FILES config/settings.conf DESTINATION /etc/dns-ad-blocker)
install(FILES config/blocklist.txt config/whitelist.txt DESTINATION /etc/dns-ad-blocker)
install(FILES dns-ad-blocker.service DESTINATION /etc/systemd/system)

set(CPACK_PACKAGE_NAME "dns-ad-blocker")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Network-level DNS ad blocker")
set(CPACK_GENERATOR "DEB;RPM;TGZ")
include(CPack)

