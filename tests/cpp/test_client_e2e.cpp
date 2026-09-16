// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Dave Robins

// End to end through the real server: spawn the wirespy_server this build
// produced, read the golden captures with the client library's pcap reader,
// decode them, and check what Wireshark says -- the C++ successor of the
// Python e2e suite (tests/python, removed 2026-09-10).
#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <filesystem>
#include <string>

#include "pcap_reader.h"
#include "wirespy_client.h"

using namespace wirespy;

#ifndef WIRESPY_SERVER_EXE
#error "WIRESPY_SERVER_EXE (the built server) must be defined"
#endif
#ifndef WIRESPY_TEST_DATA
#error "WIRESPY_TEST_DATA (tests/data) must be defined"
#endif

namespace {

// One server for the whole TU; every test gets its own connection (= session).
struct Server {
    ServerLauncher launcher;
    std::uint16_t port = 0;
    std::string error;
    Server() {
        launcher.add_candidate(WIRESPY_SERVER_EXE);
        port = launcher.ensure(error);
    }
};
Server& server() { static Server s; return s; }

std::vector<std::string> titles(WirespyClient& c) {
    nlohmann::json info; std::string err;
    std::vector<std::string> out;
    if (c.info(info, err) && info.contains("columns")) for (const auto& t : info["columns"]) out.push_back(t.get<std::string>());
    return out;
}
int col(const std::vector<std::string>& t, const char* name) {
    for (std::size_t i = 0; i < t.size(); ++i) if (t[i] == name) return (int)i;
    return -1;
}
bool has_child(const DetailNode& n, const char* name) {
    for (const DetailNode& c : n.children) if (c.name == name) return true;
    return false;
}
std::string data(const char* file) { return std::string(WIRESPY_TEST_DATA) + "/" + file; }

} // namespace

TEST_CASE("the built server starts and announces a port") {
    INFO(server().error);
    REQUIRE(server().port != 0);
}

TEST_CASE("pcap reader: the golden captures") {
    PcapFile arp;
    REQUIRE(ReadPcap(data("arp_request.pcap"), arp));
    REQUIRE(arp.frames.size() == 1);
    CHECK(arp.dlt == 1);
    CHECK(arp.frames[0].bytes.size() == 42);
    PcapFile syn;
    REQUIRE(ReadPcap(data("ipv4_tcp_syn.pcap"), syn));
    REQUIRE(syn.frames.size() == 1);
    CHECK(syn.frames[0].bytes.size() == 54);
}

TEST_CASE("pcap writer: pcap and pcapng round trip") {
    PcapFile in;
    REQUIRE(ReadPcap(data("arp_request.pcap"), in));
    in.frames[0].ts_sec = 1700000000; in.frames[0].ts_nsec = 123456789; in.frames[0].iface = "eth0";
    const std::vector<const RawFrame*> frames{&in.frames[0]};
    const auto tmp = std::filesystem::temp_directory_path() / "wirespy-e2e";
    std::string err;
    REQUIRE(WritePcap(tmp.string() + ".pcap", frames, 1, err));
    REQUIRE(WritePcap(tmp.string() + ".pcapng", frames, 1, err));
    PcapFile a, b;
    REQUIRE(ReadPcap(tmp.string() + ".pcap", a));
    REQUIRE(ReadPcap(tmp.string() + ".pcapng", b));
    REQUIRE(a.frames.size() == 1);
    REQUIRE(b.frames.size() == 1);
    CHECK(a.frames[0].bytes == in.frames[0].bytes);
    CHECK(b.frames[0].bytes == in.frames[0].bytes);
    CHECK(a.frames[0].ts_sec == 1700000000);
    CHECK(a.frames[0].ts_nsec == 123456789);
    CHECK(b.frames[0].ts_sec == 1700000000);
    CHECK(b.frames[0].ts_nsec == 123456789);
    CHECK(b.pcapng);
    std::filesystem::remove(tmp.string() + ".pcap");
    std::filesystem::remove(tmp.string() + ".pcapng");
}

TEST_CASE("e2e: ARP request -> eth + arp, Wireshark's columns") {
    REQUIRE(server().port != 0);
    WirespyClient c; std::string err;
    REQUIRE(c.connect("127.0.0.1", server().port, err));
    const auto t = titles(c);
    REQUIRE(col(t, "Protocol") >= 0);
    PcapFile cap;
    REQUIRE(ReadPcap(data("arp_request.pcap"), cap));
    DecodeAsk a;
    a.frame = std::span<const std::uint8_t>(cap.frames[0].bytes);
    a.tree = true; a.columns = true; a.color = true;
    std::vector<DecodeReply> r;
    REQUIRE(c.decode({a}, r, err));
    REQUIRE(r.size() == 1);
    REQUIRE(r[0].ok);
    CHECK(r[0].frame_number == 1);
    CHECK(r[0].has_tree);
    CHECK(has_child(r[0].tree, "frame"));
    CHECK(has_child(r[0].tree, "eth"));
    CHECK(has_child(r[0].tree, "arp"));
    CHECK(r[0].columns[(std::size_t)col(t, "Protocol")] == "ARP");
    CHECK(r[0].columns[(std::size_t)col(t, "Length")] == "42");
    CHECK(r[0].columns[(std::size_t)col(t, "Info")].find("Who has") != std::string::npos);
}

TEST_CASE("e2e: TCP SYN -> eth + ip + tcp, and a display filter") {
    REQUIRE(server().port != 0);
    WirespyClient c; std::string err;
    REQUIRE(c.connect("127.0.0.1", server().port, err));
    const auto t = titles(c);
    PcapFile cap;
    REQUIRE(ReadPcap(data("ipv4_tcp_syn.pcap"), cap));
    DecodeAsk a;
    a.frame = std::span<const std::uint8_t>(cap.frames[0].bytes);
    a.tree = true; a.columns = true;
    std::vector<DecodeReply> r;
    REQUIRE(c.decode({a}, r, err));
    REQUIRE(r[0].ok);
    CHECK(has_child(r[0].tree, "eth"));
    CHECK(has_child(r[0].tree, "ip"));
    CHECK(has_child(r[0].tree, "tcp"));
    CHECK(r[0].columns[(std::size_t)col(t, "Protocol")] == "TCP");
    CHECK(r[0].columns[(std::size_t)col(t, "Info")].find("[SYN]") != std::string::npos);

    REQUIRE(c.set_filter("arp", err));
    REQUIRE(c.decode({a}, r, err));
    CHECK_FALSE(r[0].match);
    REQUIRE(c.set_filter("tcp.flags.syn == 1", err));
    REQUIRE(c.decode({a}, r, err));
    CHECK(r[0].match);
    CHECK_FALSE(c.set_filter("tcp.flags.syn ==", err));
    CHECK_FALSE(err.empty());
}

TEST_CASE("e2e: two connections are two sessions; a transient decode keeps the sequence") {
    REQUIRE(server().port != 0);
    WirespyClient a, b; std::string err;
    REQUIRE(a.connect("127.0.0.1", server().port, err));
    REQUIRE(b.connect("127.0.0.1", server().port, err));
    PcapFile cap;
    REQUIRE(ReadPcap(data("arp_request.pcap"), cap));
    DecodeAsk ask;
    ask.frame = std::span<const std::uint8_t>(cap.frames[0].bytes);
    ask.has_ts = true; ask.ts_sec = 10;
    std::vector<DecodeReply> r;
    REQUIRE(a.decode({ask, ask, ask}, r, err));
    REQUIRE(r.size() == 3);
    CHECK(r[2].frame_number == 3);
    // b's numbering is its own
    REQUIRE(b.decode({ask}, r, err));
    CHECK(r[0].frame_number == 1);
    // a transient look at "frame 2" on b leaves both sequences alone
    DecodeAsk tr = ask;
    tr.transient = true; tr.frame_number = 2; tr.tree = true;
    tr.has_ref = true; tr.ref_ts_sec = 10;
    REQUIRE(b.decode({tr}, r, err));
    CHECK(r[0].frame_number == 2);
    CHECK(r[0].has_tree);
    REQUIRE(b.decode({ask}, r, err));
    CHECK(r[0].frame_number == 2);
    REQUIRE(a.decode({ask}, r, err));
    CHECK(r[0].frame_number == 4);
    REQUIRE(a.reset(err));
    REQUIRE(a.decode({ask}, r, err));
    CHECK(r[0].frame_number == 1);
}
