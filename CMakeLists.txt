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
