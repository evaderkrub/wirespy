// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

// wirespy_cli -- the command-line face of wirespy: dissect a capture file
// through wirespy_server and print Wireshark's summary columns, the way
// tshark's default output does, or one packet's details tree.
//
//   wirespy_cli FILE.pcap[ng] [-Y FILTER] [-V N] [--server EXE] [--json]
//
//   -Y FILTER   Wireshark display filter; only matching packets are printed
//   -V N        print packet N's details tree instead of the column table
//   --server    the wirespy_server to spawn (else WIRESPY_SERVER, then the
//               executable's own folder, then a server already on 51717)
//   --json      one JSON object per line instead of columns
//
// Exit code: 0 on success, 1 on a usage or file error, 2 when no server
// could be reached.
#include "pcap_reader.h"
#include "wirespy_client.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace wirespy;

namespace {

void PrintTree(const DetailNode& n, int depth) {
    for (const DetailNode& c : n.children) {
        if (!c.text.empty()) std::printf("%*s%s\n", depth * 4, "", c.text.c_str());
        PrintTree(c, depth + 1);
    }
}

int Usage() {
    std::fprintf(stderr, "usage: wirespy_cli FILE.pcap[ng] [-Y FILTER] [-V N] [--server EXE] [--json]\n");
    return 1;
}

} // namespace

int main(int argc, char** argv) {
    std::string file, filter, server;
    long tree_of = 0;
    bool json = false;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "-Y" && i + 1 < argc) filter = argv[++i];
        else if (a == "-V" && i + 1 < argc) tree_of = std::atol(argv[++i]);
        else if (a == "--server" && i + 1 < argc) server = argv[++i];
        else if (a == "--json") json = true;
        else if (a == "-h" || a == "--help") return Usage();
        else if (!a.empty() && a[0] == '-') return Usage();
        else file = a;
    }
    if (file.empty()) return Usage();

    PcapFile cap;
    if (!ReadPcap(file, cap)) { std::fprintf(stderr, "%s: %s\n", file.c_str(), cap.error.c_str()); return 1; }

    ServerLauncher launcher;
    if (!server.empty()) launcher.add_candidate(server);
    std::string err;
    const std::uint16_t port = launcher.ensure(err);
    if (port == 0) { std::fprintf(stderr, "%s\n", err.c_str()); return 2; }
    WirespyClient client;
    if (!client.connect("127.0.0.1", port, err)) { std::fprintf(stderr, "%s\n", err.c_str()); return 2; }
    if (!filter.empty() && !client.set_filter(filter, err)) { std::fprintf(stderr, "display filter: %s\n", err.c_str()); return 1; }

    nlohmann::json info;
    std::vector<std::string> titles;
    if (client.info(info, err) && info.contains("columns"))
        for (const auto& t : info["columns"]) titles.push_back(t.get<std::string>());

    // The whole file in order (Wireshark's relative Time and frame numbers
    // need the sequence), pipelined 128 at a time.
    std::vector<DecodeAsk> asks;
    std::vector<DecodeReply> replies;
    std::size_t shown = 0;
    for (std::size_t start = 0; start < cap.frames.size(); start += 128) {
        asks.clear();
        for (std::size_t i = start; i < cap.frames.size() && i < start + 128; ++i) {
            const RawFrame& f = cap.frames[i];
            DecodeAsk a;
            a.frame = std::span<const std::uint8_t>(f.bytes);
            a.dlt = f.dlt;
            a.has_ts = f.has_ts;
            a.ts_sec = f.ts_sec;
            a.ts_nsec = f.ts_nsec;
            a.tree = tree_of > 0 && (long)(i + 1) == tree_of;
            a.columns = true;
            a.color = json;
            asks.push_back(a);
        }
        if (!client.decode(asks, replies, err)) { std::fprintf(stderr, "%s\n", err.c_str()); return 2; }
        for (std::size_t k = 0; k < replies.size(); ++k) {
            const DecodeReply& r = replies[k];
            const std::size_t number = start + k + 1;
            if (!r.ok) { std::fprintf(stderr, "frame %zu: %s\n", number, r.error.c_str()); continue; }
            if (tree_of > 0) {
                if ((long)number == tree_of && r.has_tree) { PrintTree(r.tree, 0); ++shown; }
                continue;
            }
            if (!r.match) continue;
            ++shown;
            if (json) {
                nlohmann::json line = {{"number", number}, {"columns", r.columns}};
                if (!r.color_bg.empty()) line["color"] = {{"name", r.color_name}, {"fg", r.color_fg}, {"bg", r.color_bg}};
                std::printf("%s\n", line.dump().c_str());
            } else {
                // tshark's shape: number, time, src -> dst, protocol, length, info
                const auto col = [&](std::size_t i) { return r.columns.size() > i ? r.columns[i].c_str() : ""; };
                if (r.columns.size() >= 7)
                    std::printf("%6s %14s %-22s -> %-22s %-8s %5s %s\n", col(0), col(1), col(2), col(3), col(4), col(5), col(6));
                else
                    for (const std::string& c : r.columns) std::printf("%s\t", c.c_str()), std::printf("\n");
            }
        }
    }
    if (tree_of > 0 && shown == 0) { std::fprintf(stderr, "no packet %ld\n", tree_of); return 1; }
    return 0;
}
