#pragma once
#include <cstdint>
#include <string>
#include <vector>

// UpstreamResolver forwards raw DNS query bytes to a configurable upstream
// DNS server over UDP and returns the raw response bytes.
class UpstreamResolver {
public:
    // Construct with upstream DNS server IP and port.
    // Defaults to Google's public DNS (8.8.8.8:53).
    explicit UpstreamResolver(const std::string& dns_ip = "8.8.8.8", uint16_t port = 53);

    // Send `query` (raw DNS bytes) to the upstream server and return the response.
    // Throws std::runtime_error on socket, send, or receive failure.
    std::vector<uint8_t> resolve(const uint8_t* query, size_t length);

private:
    std::string dns_ip_;
    uint16_t port_;

    // How long to wait for a response before giving up
    static constexpr int TIMEOUT_SECONDS = 5;
};
