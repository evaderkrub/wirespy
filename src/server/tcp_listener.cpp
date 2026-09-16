// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Dave Robins

// src/server/tcp_listener.cpp -- Winsock on Windows, BSD sockets elsewhere.
#include "tcp_listener.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using sock_t = SOCKET;
static constexpr sock_t kBadSock = INVALID_SOCKET;
static void close_sock(sock_t s) { closesocket(s); }
static void wake_accept(sock_t s) { closesocket(s); }
static constexpr int kSendFlags = 0;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
using sock_t = int;
static constexpr sock_t kBadSock = -1;
static void close_sock(sock_t s) { ::close(s); }
static void wake_accept(sock_t s) { ::shutdown(s, SHUT_RDWR); ::close(s); }
static constexpr int kSendFlags = MSG_NOSIGNAL;
#endif

#include <atomic>
#include <stdexcept>
#include <thread>
#include <vector>

namespace wirespy {

struct SockInit {
#ifdef _WIN32
    SockInit()  { WSADATA d; WSAStartup(MAKEWORD(2, 2), &d); }
    ~SockInit() { WSACleanup(); }
#else
    SockInit()  { ::signal(SIGPIPE, SIG_IGN); }
#endif
};

struct TcpListener::Impl {
    SockInit init;
    std::uint16_t port;
    std::uint16_t bound = 0;
    HandlerFactory factory;
    sock_t server_sock = kBadSock;
    std::atomic<bool> stop{false};
};

TcpListener::TcpListener(std::uint16_t port, HandlerFactory factory)
    : impl_(std::make_unique<Impl>()) {
    impl_->port = port;
    impl_->factory = std::move(factory);
}

TcpListener::~TcpListener() {
    shutdown();
}

void TcpListener::shutdown() {
    impl_->stop = true;
    if (impl_->server_sock != kBadSock) {
        wake_accept(impl_->server_sock);
        impl_->server_sock = kBadSock;
    }
}

std::uint16_t TcpListener::bound_port() const { return impl_->bound; }

static bool read_exact(sock_t s, std::uint8_t* buf, std::size_t n) {
    std::size_t got = 0;
    while (got < n) {
        int r = recv(s, reinterpret_cast<char*>(buf + got),
                     static_cast<int>(n - got), 0);
        if (r <= 0) return false;
        got += static_cast<std::size_t>(r);
    }
    return true;
}

static bool write_all(sock_t s, const std::uint8_t* buf, std::size_t n) {
    std::size_t sent = 0;
    while (sent < n) {
        int r = send(s, reinterpret_cast<const char*>(buf + sent),
                     static_cast<int>(n - sent), kSendFlags);
        if (r <= 0) return false;
        sent += static_cast<std::size_t>(r);
    }
    return true;
}

static void serve_connection(sock_t sock, MessageHandler handler) {
    // Replies are small and back to back; with Nagle on, each one waited for
    // the previous one's ACK and a pipelining client saw ~2.8k replies/s
    // whatever the dissection cost. Off, the wire keeps up with epan.
    int one = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof one);
    std::vector<std::uint8_t> body;
    while (true) {
        std::uint8_t len_buf[4];
        if (!read_exact(sock, len_buf, 4)) break;
        std::uint32_t total_len =
            (std::uint32_t(len_buf[0]) << 24) |
            (std::uint32_t(len_buf[1]) << 16) |
            (std::uint32_t(len_buf[2]) << 8)  |
             std::uint32_t(len_buf[3]);
        if (total_len > kMaxRequestBytes) break;   // refuse, do not allocate
        body.resize(total_len);
        if (total_len > 0 && !read_exact(sock, body.data(), total_len)) break;

        std::vector<std::uint8_t> resp;
        try {
            resp = handler(body);
        } catch (...) {
            break;   // a handler that throws costs this connection, not the server
        }
        if (!write_all(sock, resp.data(), resp.size())) break;
    }
    close_sock(sock);
}

std::uint16_t TcpListener::listen() {
    if (impl_->server_sock != kBadSock) return impl_->bound;

    impl_->server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (impl_->server_sock == kBadSock)
        throw std::runtime_error("socket() failed");

    int yes = 1;
    setsockopt(impl_->server_sock, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&yes), sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(impl_->port);
    if (bind(impl_->server_sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
        throw std::runtime_error("bind() failed");
    if (::listen(impl_->server_sock, 8) < 0)
        throw std::runtime_error("listen() failed");

    sockaddr_in got{};
#ifdef _WIN32
    int len = sizeof(got);
#else
    socklen_t len = sizeof(got);
#endif
    if (getsockname(impl_->server_sock, reinterpret_cast<sockaddr*>(&got), &len) == 0)
        impl_->bound = ntohs(got.sin_port);
    else
        impl_->bound = impl_->port;
    return impl_->bound;
}

void TcpListener::run() {
    listen();
    while (!impl_->stop) {
        sock_t client = accept(impl_->server_sock, nullptr, nullptr);
        if (client == kBadSock) {
            if (impl_->stop) break;
            continue;
        }
        std::thread(serve_connection, client, impl_->factory()).detach();
    }
}

} // namespace wirespy
