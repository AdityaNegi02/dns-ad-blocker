#include "resolver/upstream_resolver.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdexcept>
#include <cstring>

UpstreamResolver::UpstreamResolver(const std::string& dns_ip, uint16_t port)
    : dns_ip_(dns_ip), port_(port) {}

// ---------------------------------------------------------------------------
// resolve
// ---------------------------------------------------------------------------
// Creates a one-shot UDP socket, sets a receive timeout, sends the raw query,
// reads the response, and returns it as a byte vector.
std::vector<uint8_t> UpstreamResolver::resolve(const uint8_t* query, size_t length) {
    // Create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        throw std::runtime_error("UpstreamResolver: failed to create socket");
    }

    // Set receive timeout so we don't block forever if the upstream is unreachable
    struct timeval tv{};
    tv.tv_sec  = TIMEOUT_SECONDS;
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        close(sock);
        throw std::runtime_error("UpstreamResolver: failed to set socket timeout");
    }

    // Destination address: upstream DNS server
    struct sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port   = htons(port_);
    if (inet_pton(AF_INET, dns_ip_.c_str(), &dest.sin_addr) != 1) {
        close(sock);
        throw std::runtime_error("UpstreamResolver: invalid upstream DNS IP: " + dns_ip_);
    }

    // Send the query
    ssize_t sent = sendto(sock, query, length, 0,
                          reinterpret_cast<struct sockaddr*>(&dest), sizeof(dest));
    if (sent < 0 || static_cast<size_t>(sent) != length) {
        close(sock);
        throw std::runtime_error("UpstreamResolver: failed to send query");
    }

    // Receive the response (DNS over UDP is limited to 512 bytes per RFC 1035)
    uint8_t buf[512];
    struct sockaddr_in from{};
    socklen_t from_len = sizeof(from);
    ssize_t received = recvfrom(sock, buf, sizeof(buf), 0,
                                reinterpret_cast<struct sockaddr*>(&from), &from_len);
    close(sock);

    if (received < 0) {
        throw std::runtime_error("UpstreamResolver: no response from upstream DNS (timeout)");
    }

    return std::vector<uint8_t>(buf, buf + received);
}
