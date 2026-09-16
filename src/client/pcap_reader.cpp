// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

// pcap_reader.cpp
#include "pcap_reader.h"

#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>

namespace wirespy {

namespace {

struct Cursor {
    const std::uint8_t* p;
    std::size_t n;
    bool le;
    std::uint16_t u16(std::size_t off) const {
        return le ? (std::uint16_t)(p[off] | (p[off + 1] << 8))
                  : (std::uint16_t)((p[off] << 8) | p[off + 1]);
    }
    std::uint32_t u32(std::size_t off) const {
        return le ? ((std::uint32_t)p[off] | ((std::uint32_t)p[off + 1] << 8) |
                     ((std::uint32_t)p[off + 2] << 16) | ((std::uint32_t)p[off + 3] << 24))
                  : (((std::uint32_t)p[off] << 24) | ((std::uint32_t)p[off + 1] << 16) |
                     ((std::uint32_t)p[off + 2] << 8) | (std::uint32_t)p[off + 3]);
    }
};

bool ReadClassic(const std::vector<std::uint8_t>& d, PcapFile& out) {
    if (d.size() < 24) { out.error = "file too short for a pcap header"; return false; }
    const std::uint32_t magic_be = ((std::uint32_t)d[0] << 24) | ((std::uint32_t)d[1] << 16) |
                                   ((std::uint32_t)d[2] << 8) | d[3];
    bool le = false, nsec = false;
    switch (magic_be) {
    case 0xa1b2c3d4u: le = false; nsec = false; break;
    case 0xd4c3b2a1u: le = true;  nsec = false; break;
    case 0xa1b23c4du: le = false; nsec = true;  break;
    case 0x4d3cb2a1u: le = true;  nsec = true;  break;
    default:
        char buf[64];
        std::snprintf(buf, sizeof buf, "unknown pcap magic 0x%08x", magic_be);
        out.error = buf;
        return false;
    }
    Cursor c{d.data(), d.size(), le};
    out.dlt = (int)(c.u32(20) & 0x0fffffffu);   // upper nibble: FCS presence
    std::size_t pos = 24;
    while (pos + 16 <= d.size()) {
        const std::uint32_t ts_sec = c.u32(pos), ts_frac = c.u32(pos + 4);
        const std::uint32_t caplen = c.u32(pos + 8), origlen = c.u32(pos + 12);
        pos += 16;
        if (pos + caplen > d.size()) { out.error = "truncated packet record"; break; }
        RawFrame f;
        f.bytes.assign(d.begin() + (std::ptrdiff_t)pos, d.begin() + (std::ptrdiff_t)(pos + caplen));
        f.orig_len = origlen;
        f.ts_sec = ts_sec;
        f.ts_nsec = (std::int32_t)(nsec ? ts_frac : ts_frac * 1000u);
        f.dlt = out.dlt;
        out.frames.push_back(std::move(f));
        pos += caplen;
    }
    return true;
}

bool ReadPcapNg(const std::vector<std::uint8_t>& d, PcapFile& out) {
    out.pcapng = true;
    struct Iface { int dlt; std::uint64_t tsdiv; bool nano; std::string name; };
    std::vector<Iface> ifaces;
    bool le = true;
    std::size_t pos = 0;
    bool any_dlt = false;
    while (pos + 12 <= d.size()) {
        // Every block: type(4) len(4) ... len(4). The SHB's byte-order magic
        // sets the endianness for the section.
        const std::uint32_t type_le = (std::uint32_t)d[pos] | ((std::uint32_t)d[pos + 1] << 8) |
                                      ((std::uint32_t)d[pos + 2] << 16) | ((std::uint32_t)d[pos + 3] << 24);
        if (type_le == 0x0a0d0d0au) {
            if (pos + 12 > d.size()) break;
            const std::uint32_t bom_le = (std::uint32_t)d[pos + 8] | ((std::uint32_t)d[pos + 9] << 8) |
                                         ((std::uint32_t)d[pos + 10] << 16) | ((std::uint32_t)d[pos + 11] << 24);
            le = (bom_le == 0x1a2b3c4du);
            ifaces.clear();
        }
        Cursor c{d.data(), d.size(), le};
        const std::uint32_t type = c.u32(pos);
        const std::uint32_t len = c.u32(pos + 4);
        if (len < 12 || pos + len > d.size()) { out.error = "truncated pcapng block"; break; }
        const std::size_t body = pos + 8, body_len = len - 12;
        if (type == 1u) {   // Interface Description Block
            Iface f{1, 1000000ull, false, {}};
            if (body_len >= 8) f.dlt = c.u16(body);
            // options: tsresol (9), name (2)
            std::size_t o = body + 8;
            const std::size_t end = body + body_len;
            while (o + 4 <= end) {
                const std::uint16_t code = c.u16(o), olen = c.u16(o + 2);
                o += 4;
                if (o + olen > end) break;
                if (code == 0) break;
                if (code == 9 && olen >= 1) {
                    const std::uint8_t r = d[o];
                    if (r & 0x80) f.tsdiv = 1ull << (r & 0x7f);
                    else { f.tsdiv = 1; for (int i = 0; i < (r & 0x7f); ++i) f.tsdiv *= 10ull; }
                } else if (code == 2) {
                    f.name.assign((const char*)&d[o], olen);
                }
                o += (olen + 3u) & ~3u;
            }
            if (!any_dlt) { out.dlt = f.dlt; any_dlt = true; }
            ifaces.push_back(f);
        } else if (type == 6u || type == 3u) {   // Enhanced / Simple Packet Block
            RawFrame f;
            std::size_t data_off, caplen, origlen;
            const Iface* ifc = nullptr;
            if (type == 6u) {
                if (body_len < 20) { pos += len; continue; }
                const std::uint32_t ifid = c.u32(body);
                const std::uint64_t ts = ((std::uint64_t)c.u32(body + 4) << 32) | c.u32(body + 8);
                caplen = c.u32(body + 12);
                origlen = c.u32(body + 16);
                data_off = body + 20;
                if (ifid < ifaces.size()) ifc = &ifaces[ifid];
                const std::uint64_t div = ifc ? ifc->tsdiv : 1000000ull;
                f.ts_sec = (std::int64_t)(ts / div);
                const std::uint64_t rem = ts % div;
                f.ts_nsec = (std::int32_t)(div == 0 ? 0 : (rem * 1000000000ull) / div);
            } else {
                if (body_len < 4) { pos += len; continue; }
                origlen = c.u32(body);
                caplen = body_len - 4;
                // A SPB's captured length is the IDB's snaplen; clamp to the block.
                data_off = body + 4;
                if (!ifaces.empty()) ifc = &ifaces[0];
                f.has_ts = false;
            }
            if (data_off + caplen > pos + len) caplen = (pos + len) - data_off;
            f.bytes.assign(d.begin() + (std::ptrdiff_t)data_off, d.begin() + (std::ptrdiff_t)(data_off + caplen));
            f.orig_len = (std::uint32_t)origlen;
            f.dlt = ifc ? ifc->dlt : out.dlt;
            if (ifc) f.iface = ifc->name;
            out.frames.push_back(std::move(f));
        }
        pos += len;
    }
    return true;
}

} // namespace

bool ReadPcap(const std::string& path, PcapFile& out) {
    out = PcapFile{};
    std::ifstream in(path, std::ios::binary);
    if (!in) { out.error = "cannot open " + path; return false; }
    std::vector<std::uint8_t> d((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (d.size() < 4) { out.error = "file too short"; return false; }
    const std::uint32_t first_le = (std::uint32_t)d[0] | ((std::uint32_t)d[1] << 8) |
                                   ((std::uint32_t)d[2] << 16) | ((std::uint32_t)d[3] << 24);
    if (first_le == 0x0a0d0d0au) return ReadPcapNg(d, out);
    return ReadClassic(d, out);
}

namespace {
bool EndsWithNoCase(const std::string& s, const char* suffix) {
    const std::size_t n = std::strlen(suffix);
    if (s.size() < n) return false;
    for (std::size_t i = 0; i < n; ++i)
        if (std::tolower((unsigned char)s[s.size() - n + i]) != std::tolower((unsigned char)suffix[i])) return false;
    return true;
}
} // namespace

bool WritePcapNg(const std::string& path, const std::vector<const RawFrame*>& frames, std::string& error) {
    std::ofstream o(path, std::ios::binary | std::ios::trunc);
    if (!o) { error = "cannot write " + path; return false; }
    std::string buf;
    auto w16 = [&](std::uint16_t v) { buf.push_back((char)v); buf.push_back((char)(v >> 8)); };
    auto w32 = [&](std::uint32_t v) { for (int i = 0; i < 4; ++i) buf.push_back((char)(v >> (8 * i))); };
    auto pad = [&]() { while (buf.size() % 4) buf.push_back('\0'); };
    auto block = [&](std::uint32_t type, const std::string& body) {
        const std::uint32_t len = (std::uint32_t)(12 + body.size());
        std::string b;
        for (int i = 0; i < 4; ++i) b.push_back((char)(type >> (8 * i)));
        for (int i = 0; i < 4; ++i) b.push_back((char)(len >> (8 * i)));
        b += body;
        for (int i = 0; i < 4; ++i) b.push_back((char)(len >> (8 * i)));
        o.write(b.data(), (std::streamsize)b.size());
    };
    // Section Header Block
    buf.clear();
    w32(0x1a2b3c4du); w16(1); w16(0);
    w32(0xffffffffu); w32(0xffffffffu);   // section length unknown
    { const std::string app = "wirespy"; w16(4); w16((std::uint16_t)app.size()); buf += app; pad(); }   // shb_userappl
    w16(0); w16(0);
    block(0x0a0d0d0au, buf);
    // One Interface Description Block per link type, nanosecond resolution.
    std::vector<int> dlts;
    auto iface_of = [&](int dlt) {
        for (std::size_t i = 0; i < dlts.size(); ++i) if (dlts[i] == dlt) return (std::uint32_t)i;
        dlts.push_back(dlt);
        buf.clear();
        w16((std::uint16_t)dlt); w16(0); w32(262144);
        w16(9); w16(1); buf.push_back(9); pad();   // if_tsresol: 10^-9
        w16(0); w16(0);
        block(1u, buf);
        return (std::uint32_t)(dlts.size() - 1);
    };
    for (const RawFrame* f : frames) {
        const std::uint32_t ifid = iface_of(f->dlt);
        buf.clear();
        w32(ifid);
        const std::uint64_t ts = (std::uint64_t)f->ts_sec * 1000000000ull + (std::uint64_t)(f->ts_nsec < 0 ? 0 : f->ts_nsec);
        w32((std::uint32_t)(ts >> 32)); w32((std::uint32_t)ts);
        w32((std::uint32_t)f->bytes.size());
        w32(f->orig_len ? f->orig_len : (std::uint32_t)f->bytes.size());
        buf.append((const char*)f->bytes.data(), f->bytes.size()); pad();
        if (!f->iface.empty()) { w16(1); w16((std::uint16_t)f->iface.size()); buf += f->iface; pad(); }   // opt_comment
        w16(0); w16(0);
        block(6u, buf);
    }
    if (!o) { error = "write failed: " + path; return false; }
    return true;
}

bool WritePcap(const std::string& path, const std::vector<const RawFrame*>& frames,
               int dlt, std::string& error) {
    if (EndsWithNoCase(path, ".pcapng")) return WritePcapNg(path, frames, error);
    std::ofstream o(path, std::ios::binary | std::ios::trunc);
    if (!o) { error = "cannot write " + path; return false; }
    auto w32 = [&](std::uint32_t v) {
        const std::uint8_t b[4] = {(std::uint8_t)v, (std::uint8_t)(v >> 8), (std::uint8_t)(v >> 16), (std::uint8_t)(v >> 24)};
        o.write((const char*)b, 4);
    };
    auto w16 = [&](std::uint16_t v) {
        const std::uint8_t b[2] = {(std::uint8_t)v, (std::uint8_t)(v >> 8)};
        o.write((const char*)b, 2);
    };
    w32(0xa1b23c4du);   // nanosecond pcap, little-endian
    w16(2); w16(4);
    w32(0); w32(0);
    w32(262144);
    w32((std::uint32_t)dlt);
    for (const RawFrame* f : frames) {
        w32((std::uint32_t)f->ts_sec);
        w32((std::uint32_t)f->ts_nsec);
        w32((std::uint32_t)f->bytes.size());
        w32(f->orig_len ? f->orig_len : (std::uint32_t)f->bytes.size());
        o.write((const char*)f->bytes.data(), (std::streamsize)f->bytes.size());
    }
    if (!o) { error = "write failed: " + path; return false; }
    return true;
}

} // namespace wirespy
