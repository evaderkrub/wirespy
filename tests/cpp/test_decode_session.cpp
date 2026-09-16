// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Dave Robins

#include <catch2/catch_test_macros.hpp>
#include <functional>
#include <memory>
#include "decode_session.hpp"
#include "epan_runtime.hpp"

using namespace wirespy;

namespace {
// Process-global EpanRuntime — libwireshark init is only safe once per
// process, so we lazily construct a single instance shared across all
// DecodeSession tests in this TU.
EpanRuntime& shared_epan() {
    static EpanRuntime epan("wirespy_tests");
    return epan;
}

bool tree_has(const RenderNode& n, const char* name) {
    if (n.name == name) return true;
    for (auto& c : n.children) if (tree_has(c, name)) return true;
    return false;
}

int col_index(const DecodeSession& s, const char* title) {
    auto titles = s.column_titles();
    for (std::size_t i = 0; i < titles.size(); ++i) if (titles[i] == title) return (int)i;
    return -1;
}
} // namespace

// Minimal Ethernet+IPv4+ICMP echo request frame (74 bytes)
static const std::uint8_t kIcmpFrame[] = {
    // Ethernet: dst, src, type=IPv4
    0x00,0x11,0x22,0x33,0x44,0x55, 0xaa,0xbb,0xcc,0xdd,0xee,0xff, 0x08,0x00,
    // IPv4: version+ihl, dscp, total_len=60, id, flags+frag, ttl=64, proto=ICMP, csum
    0x45,0x00,0x00,0x3c,0x00,0x01,0x00,0x00,0x40,0x01,0xb7,0x4a,
    // src=10.0.0.1, dst=10.0.0.2
    0x0a,0x00,0x00,0x01, 0x0a,0x00,0x00,0x02,
    // ICMP: type=8 (echo req), code=0, csum, id, seq, 32 bytes payload
    0x08,0x00,0x4d,0x35, 0x00,0x01,0x00,0x01,
    'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p',
    'q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5'
};

TEST_CASE("DecodeSession decodes ICMP echo request") {
    (void)shared_epan();

    DecodeSession session;
    auto tree = session.decode(std::span(kIcmpFrame, sizeof(kIcmpFrame)),
                               dlt_from_name("EN10MB"));

    REQUIRE(tree.name == "frame");
    REQUIRE(tree_has(tree, "eth"));
    REQUIRE(tree_has(tree, "ip"));
    REQUIRE(tree_has(tree, "icmp"));
}

TEST_CASE("dlt_from_name") {
    REQUIRE(dlt_from_name("EN10MB") == 1);
    REQUIRE(dlt_from_name("RAW") == 101);
    REQUIRE(dlt_from_name("nope") == -1);
}

TEST_CASE("DecodeSession increments frame count and reset restarts it") {
    (void)shared_epan();
    DecodeSession session;
    session.decode(std::span(kIcmpFrame, sizeof(kIcmpFrame)), dlt_from_name("EN10MB"));
    session.decode(std::span(kIcmpFrame, sizeof(kIcmpFrame)), dlt_from_name("EN10MB"));
    REQUIRE(session.frame_count() == 2);
    session.reset();
    DecodeRequest r;
    r.frame = std::span(kIcmpFrame, sizeof(kIcmpFrame));
    REQUIRE(session.decode(r).frame_number == 1);
}

TEST_CASE("DecodeSession fills Wireshark's summary columns") {
    (void)shared_epan();
    DecodeSession session;
    const int proto = col_index(session, "Protocol");
    const int info = col_index(session, "Info");
    const int src = col_index(session, "Source");
    const int dst = col_index(session, "Destination");
    const int len = col_index(session, "Length");
    const int time = col_index(session, "Time");
    REQUIRE(proto >= 0);
    REQUIRE(info >= 0);
    REQUIRE(src >= 0);

    DecodeRequest r;
    r.frame = std::span(kIcmpFrame, sizeof(kIcmpFrame));
    r.want_tree = false;
    r.want_columns = true;
    r.has_ts = true;
    r.ts_sec = 1000;
    r.ts_nsec = 0;
    DecodeOutput a = session.decode(r);
    REQUIRE(a.columns.size() == session.column_titles().size());
    CHECK(a.columns[(size_t)proto] == "ICMP");
    CHECK(a.columns[(size_t)info].find("Echo (ping) request") != std::string::npos);
    CHECK(a.columns[(size_t)src] == "10.0.0.1");
    CHECK(a.columns[(size_t)dst] == "10.0.0.2");
    CHECK(a.columns[(size_t)len] == "74");
    CHECK(a.tree.children.empty());

    // The default Time column is relative to the first frame.
    r.ts_sec = 1001;
    r.ts_nsec = 500000000;
    DecodeOutput b = session.decode(r);
    REQUIRE(time >= 0);
    CHECK(b.columns[(size_t)time].rfind("1.5", 0) == 0);
}

TEST_CASE("DecodeSession applies a display filter") {
    (void)shared_epan();
    DecodeSession session;
    std::string err;
    REQUIRE(session.set_filter("icmp", err));
    DecodeRequest r;
    r.frame = std::span(kIcmpFrame, sizeof(kIcmpFrame));
    r.want_tree = false;
    CHECK(session.decode(r).filter_matched);

    REQUIRE(session.set_filter("tcp.port == 80", err));
    CHECK_FALSE(session.decode(r).filter_matched);

    REQUIRE_FALSE(session.set_filter("this is not a filter ===", err));
    CHECK_FALSE(err.empty());
    CHECK(session.filter() == "tcp.port == 80");   // the bad one changed nothing

    REQUIRE(session.set_filter("", err));
    CHECK(session.decode(r).filter_matched);
}

TEST_CASE("DecodeSession reports the colouring rule") {
    if (!shared_epan().colors_loaded()) {
        SUCCEED("no colorfilters file on this machine");
        return;
    }
    DecodeSession session;
    DecodeRequest r;
    r.frame = std::span(kIcmpFrame, sizeof(kIcmpFrame));
    r.want_tree = false;
    r.want_color = true;
    DecodeOutput o = session.decode(r);
    CHECK(o.color_name == "ICMP");
    CHECK(o.color_bg.size() == 7);
    CHECK(o.color_fg.size() == 7);
}

TEST_CASE("A transient decode leaves the sequence untouched") {
    (void)shared_epan();
    DecodeSession session;
    const int time = col_index(session, "Time");
    DecodeRequest r;
    r.frame = std::span(kIcmpFrame, sizeof(kIcmpFrame));
    r.want_tree = false;
    r.want_columns = true;
    r.has_ts = true;
    r.ts_sec = 10;
    session.decode(r);              // frame 1 at t=10
    r.ts_sec = 12;
    session.decode(r);              // frame 2 at t=12 -> Time 2.0

    DecodeRequest t = r;            // re-dissect "frame 2" for its details
    t.transient = true;
    t.frame_number = 2;
    t.has_ref = true;  t.ref_ts_sec = 10;
    t.has_prev = true; t.prev_ts_sec = 10;
    t.want_tree = true;
    DecodeOutput d = session.decode(t);
    CHECK(d.frame_number == 2);
    CHECK(d.columns[(size_t)time].rfind("2.0", 0) == 0);
    CHECK_FALSE(d.tree.children.empty());
    CHECK(session.frame_count() == 2);   // not advanced

    r.ts_sec = 13;
    DecodeOutput e = session.decode(r);  // the in-order pass continues as if nothing happened
    CHECK(e.frame_number == 3);
    CHECK(e.columns[(size_t)time].rfind("3.0", 0) == 0);
}
