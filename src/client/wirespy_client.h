// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

// wirespy_client.h -- the C++ client for wirespy_server: a blocking TCP
// client that pipelines requests, and the launcher that finds or spawns a
// server for it to talk to. Links nothing from Wireshark: the dissector is
// GPL and stays in the server process; this library is the client side of
// the protocol in docs/PROTOCOL.md. See the licensing documentation.
#pragma once
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace wirespy {

// A decoded node of Wireshark's packet-details tree.
struct DetailNode {
    std::string name;       // "ip.src"
    std::string text;       // "Source Address: 10.0.0.1"
    int pos = 0, size = 0;  // byte span in the frame
    std::vector<DetailNode> children;
};

struct DecodeReply {
    bool ok = false;
    std::string error;
    std::uint32_t frame_number = 0;
    bool match = true;
    std::vector<std::string> columns;
    std::string color_name, color_fg, color_bg;   // "#rrggbb"
    DetailNode tree;
    bool has_tree = false;
};

struct DecodeAsk {
    std::span<const std::uint8_t> frame;
    int dlt = 1;
    bool has_ts = false;
    std::int64_t ts_sec = 0;
    std::int32_t ts_nsec = 0;
    bool tree = false;
    bool columns = true;
    bool color = true;
    // A transient decode (a details pane) reproduces one frame's place in
    // the sequence without advancing the server's numbering.
    bool transient = false;
    std::uint32_t frame_number = 0;
    bool has_ref = false;
    std::int64_t ref_ts_sec = 0;
    std::int32_t ref_ts_nsec = 0;
    bool has_prev = false;
    std::int64_t prev_ts_sec = 0;
    std::int32_t prev_ts_nsec = 0;
};

class WirespyClient {
public:
    WirespyClient();
    ~WirespyClient();
    WirespyClient(const WirespyClient&) = delete;
    WirespyClient& operator=(const WirespyClient&) = delete;

    bool connect(const std::string& host, std::uint16_t port, std::string& error);
    void close();
    bool connected() const { return sock_ >= 0; }

    // Pipelined: every ask is written, then every reply read, in order.
    bool decode(const std::vector<DecodeAsk>& asks, std::vector<DecodeReply>& out, std::string& error);
    bool set_filter(const std::string& text, std::string& error);   // error = why it failed to compile
    bool reset(std::string& error);
    bool info(nlohmann::json& out, std::string& error);

private:
    bool send_request(const nlohmann::json& header, std::span<const std::uint8_t> frame, std::string& error);
    bool read_reply(nlohmann::json& out, std::string& error);
    long long sock_ = -1;
};

// Finds a server to talk to. Order: the WIRESPY_SERVER environment variable
// (a path), <exe dir>/wirespy/wirespy_server[.exe], <exe dir>/wirespy_server,
// then an already-running server on the default port 51717. A spawned
// server gets --port 0 --parent-pid <us> (and --data-dir <dir>/share/wireshark
// when that folder sits beside it, the MSYS2 staging layout) and announces
// its port on stdout.
class ServerLauncher {
public:
    ~ServerLauncher();
    // Returns the port to connect to, 0 on failure (with `error`).
    std::uint16_t ensure(std::string& error);
    void stop();
    std::string description() const { return desc_; }
    bool spawned() const { return pid_ != 0; }
    // Extra candidates tried FIRST (a test's freshly built server, a --server flag).
    void add_candidate(const std::string& exe) { extra_.push_back(exe); }
private:
    std::uint16_t spawn(const std::string& exe, std::string& error);
    std::vector<std::string> extra_;
    long long pid_ = 0;
    std::uint16_t port_ = 0;
    std::string desc_;
};

std::string ExeDir();

} // namespace wirespy
