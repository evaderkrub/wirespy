// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Dave Robins

// src/server/decode_session.hpp
#pragma once
#include "tree_render.hpp"
#include <cstdint>
#include <span>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace wirespy {

// What to do with one frame. Everything but `frame` has a default that
// reproduces the original single-purpose decode (a full tree, no columns).
struct DecodeRequest {
    std::span<const std::uint8_t> frame;
    int link_type_dlt = 1;             // libpcap DLT, 1 = EN10MB
    bool has_ts = false;               // false: the frame has no timestamp
    std::int64_t ts_sec = 0;
    std::int32_t ts_nsec = 0;
    bool want_tree = true;             // packet-details tree with text
    bool want_columns = false;         // Wireshark's summary columns
    bool want_color = false;           // the colouring rule that matched

    // A TRANSIENT decode leaves the session's numbering and timing untouched:
    // a GUI re-dissecting one packet for its details pane while another
    // connection walks the capture in order. frame_number is what the frame
    // is called (0 = next in sequence); ref/prev timestamps reproduce the
    // relative and delta times the in-order pass had.
    bool transient = false;
    std::uint32_t frame_number = 0;
    bool has_ref = false;
    std::int64_t ref_ts_sec = 0;
    std::int32_t ref_ts_nsec = 0;
    bool has_prev = false;
    std::int64_t prev_ts_sec = 0;
    std::int32_t prev_ts_nsec = 0;
};

// Wireshark's answer for one frame.
struct DecodeOutput {
    std::uint32_t frame_number = 0;    // 1-based, per session, reset() restarts
    RenderNode tree;                   // childless "frame" root when !want_tree
    // One text per configured column, in column_titles() order (the
    // profile's list: No., Time, Source, Destination, Protocol, Length, Info).
    std::vector<std::string> columns;
    bool filter_matched = true;        // the session's display filter (true when none)
    std::string color_name;            // colouring rule name, "" when none matched
    std::string color_fg, color_bg;    // "#rrggbb", "" when none matched
};

class DecodeSession {
public:
    DecodeSession();
    ~DecodeSession();
    DecodeSession(const DecodeSession&) = delete;
    DecodeSession& operator=(const DecodeSession&) = delete;

    // Dissect one frame. Throws std::runtime_error on an unusable link type.
    DecodeOutput decode(const DecodeRequest& req);

    // The original entry point: full tree, no timestamp, no columns.
    RenderNode decode(std::span<const std::uint8_t> frame, int link_type_dlt);

    // Wireshark display filter applied to every later decode ("" clears).
    // Returns false and fills `error` when the text does not compile; the
    // previous filter stays in force.
    bool set_filter(std::string_view text, std::string& error);
    const std::string& filter() const { return filter_text_; }

    // A new capture: frame numbering and the time reference start over.
    void reset();

    int frame_count() const { return frame_count_; }

    // Titles of the columns decode() fills, in order.
    std::vector<std::string> column_titles() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    int frame_count_ = 0;
    std::string filter_text_;
};

// "EN10MB" -> 1, "LINUX_SLL" -> 113, etc. Returns -1 for unknown.
int dlt_from_name(std::string_view name);

// The names dlt_from_name() knows, for the "info" reply.
std::vector<std::string> known_link_types();

} // namespace wirespy
