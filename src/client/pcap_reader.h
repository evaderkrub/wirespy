// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

// pcap_reader.h -- classic pcap (both endians, microsecond and nanosecond
// magics) and pcapng (SHB / IDB / EPB / SPB, per-interface link type and
// tsresol). Reads the whole file into memory: captures a user opens in a GUI
// fit, and it keeps the reader a few dozen lines. Also the matching classic
// pcap writer for Save As.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace wirespy {

// One captured frame, as every source and file hands it over.
struct RawFrame {
    std::vector<std::uint8_t> bytes;   // the whole frame, MAC header first
    std::uint32_t orig_len = 0;        // on the wire; == bytes.size() unless truncated
    std::int64_t ts_sec = 0;           // capture time (epoch or capture-relative)
    std::int32_t ts_nsec = 0;
    bool has_ts = true;
    int dlt = 1;                       // libpcap link type; 1 = Ethernet
    std::string iface;                 // where it was seen (interface / network name)
    bool transmitted = false;          // the source sent it rather than received it
};


struct PcapFile {
    std::vector<RawFrame> frames;
    int dlt = 1;                   // the file's (first interface's) link type
    bool pcapng = false;
    std::string error;             // non-empty = failed; frames may be partial
};

// Returns false and fills out.error on a file that cannot be read at all.
bool ReadPcap(const std::string& path, PcapFile& out);

// Writes the capture: pcapng when the path ends in .pcapng (one interface
// per link type, nanosecond resolution, interface names carried as
// comments), classic nanosecond pcap otherwise. Returns false + error.
bool WritePcap(const std::string& path, const std::vector<const RawFrame*>& frames,
               int dlt, std::string& error);
bool WritePcapNg(const std::string& path, const std::vector<const RawFrame*>& frames,
                 std::string& error);

} // namespace wirespy
