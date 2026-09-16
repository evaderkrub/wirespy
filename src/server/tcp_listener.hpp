// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Dave Robins

// src/server/tcp_listener.hpp
#pragma once
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <vector>

namespace wirespy {

// Per-message handler: receives the request body (the bytes after the
// outer total_len prefix), returns the full response bytes ready to write
// to the socket (already prefixed with total_len).
using MessageHandler = std::function<std::vector<std::uint8_t>(
    std::span<const std::uint8_t> body)>;

// Per-connection handler factory: returns a fresh MessageHandler for a new
// connection. The factory itself is shared across threads (must be reentrant).
// The returned handler is owned by one thread.
using HandlerFactory = std::function<MessageHandler()>;

// Largest request body accepted; anything bigger closes the connection
// (the outer length is client-controlled and used to size an allocation).
constexpr std::uint32_t kMaxRequestBytes = 64u * 1024u * 1024u;

class TcpListener {
public:
    // port 0 = let the OS pick; read it back with bound_port() after
    // listen() (run() calls listen() itself if it has not happened yet).
    TcpListener(std::uint16_t port, HandlerFactory factory);
    ~TcpListener();

    // Bind + listen on 127.0.0.1 and return the bound port. Idempotent.
    std::uint16_t listen();
    std::uint16_t bound_port() const;

    void run();      // blocks; returns on shutdown
    void shutdown();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace wirespy
