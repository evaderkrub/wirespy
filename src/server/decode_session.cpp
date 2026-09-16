// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Dave Robins

// src/server/decode_session.cpp
#include "decode_session.hpp"

#include <cstdio>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>

// Wireshark headers handle their own extern "C" via __cplusplus guards.
// Do NOT wrap them in extern "C" here.
#include <ws_version.h>
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/proto.h>
#include <epan/frame_data.h>
#include <epan/tvbuff.h>
#include <epan/column.h>
#include <epan/column-info.h>
#include <epan/column-utils.h>
#include <epan/color_filters.h>
#include <epan/prefs.h>
#include <epan/dfilter/dfilter.h>
#include <wiretap/wtap.h>
#include <wiretap/pcap-encap.h>
#include <wsutil/buffer.h>
#include <wsutil/nstime.h>

#include "ws_compat.hpp"

// libwireshark only forward-declares this; the application owns its shape.
// It answers frame-number -> timestamp lookups (frame.time_relative,
// frame.time_delta_displayed and the default relative-time column all go
// through epan_get_frame_ts). The table itself belongs to whichever
// DecodeSession is dissecting: the pointer is swapped in before each run.
struct packet_provider_data {
    const std::vector<nstime_t>* ts = nullptr;   // index frame_number - 1
};

namespace wirespy {

namespace {

const std::unordered_map<std::string, int>& dlt_table() {
    // libpcap DLT_* / LINKTYPE_* numbers (pcap/dlt.h). RAW is 101, the
    // portable LINKTYPE_RAW -- 12 is DLT_RAW on Linux but DLT_LOOP on OpenBSD.
    static const std::unordered_map<std::string, int> map = {
        {"NULL", 0},
        {"EN10MB", 1},
        {"IEEE802_11", 105},
        {"LINUX_SLL", 113},
        {"RAW", 101},
        {"IPV4", 228},
        {"IPV6", 229},
        {"CAN_SOCKETCAN", 227},
        {"USER0", 147},
    };
    return map;
}

} // namespace

int dlt_from_name(std::string_view name) {
    auto it = dlt_table().find(std::string(name));
    return it == dlt_table().end() ? -1 : it->second;
}

std::vector<std::string> known_link_types() {
    std::vector<std::string> out;
    for (const auto& [k, v] : dlt_table()) out.push_back(k);
    return out;
}

// packet_provider_funcs: epan_new() memcpy's from it unconditionally, so a
// real struct is required. The frame dissector calls get_interface_name to
// fill columns and asserts on a NULL string, hence the empty strings.
static const nstime_t* prov_frame_ts(struct packet_provider_data* prov, uint32_t frame_num) {
    if (!prov || !prov->ts || frame_num == 0 || frame_num > prov->ts->size()) return nullptr;
    return &(*prov->ts)[frame_num - 1];
}
static const char* prov_iface_name(struct packet_provider_data*, uint32_t, unsigned) {
    return "";
}
static const char* prov_iface_desc(struct packet_provider_data*, uint32_t, unsigned) {
    return "";
}
static const struct packet_provider_funcs kProviderFuncs = {
    /*get_frame_ts*/             prov_frame_ts,
    /*get_interface_name*/       prov_iface_name,
    /*get_interface_description*/prov_iface_desc,
    /*get_modified_block*/       nullptr,
#if WIRESPY_WS_AT_LEAST(4, 5)
    /*get_process_id*/           nullptr,
    /*get_process_name*/         nullptr,
    /*get_process_uuid*/         nullptr,
#endif
};

// ONE epan_t per process. epan_new() enters libwireshark's file memory scope
// and epan_free() leaves it, and the scope asserts on a second entry -- so a
// second concurrent DecodeSession (one per TCP connection) took the server
// down with "wmem_enter_file_scope(): assertion failed: !wmem_in_scope".
// Every DecodeSession keeps its own numbering, timestamps, columns and
// filter; the epan session and its packet provider are shared and
// reference-counted here. The provider's timestamp table is pointed at the
// dissecting session for the duration of each run (the caller serialises
// dissection: libwireshark is single-threaded anyway).
struct SharedEpan {
    std::mutex m;
    epan_t* session = nullptr;
    packet_provider_data prov;
    int refs = 0;
    static SharedEpan& Get() { static SharedEpan s; return s; }
    epan_t* Acquire() {
        std::lock_guard<std::mutex> g(m);
        if (refs++ == 0) session = epan_new(&prov, &kProviderFuncs);
        return session;
    }
    void Release() {
        std::lock_guard<std::mutex> g(m);
        if (--refs == 0 && session) { epan_free(session); session = nullptr; prov.ts = nullptr; }
    }
};

struct DecodeSession::Impl {
    std::vector<nstime_t> ts;   // this session's frame timestamps, index frame_number - 1
    epan_t* session = nullptr;
    column_info cinfo{};
    bool have_columns = false;
    dfilter_t* df = nullptr;
    // Time bookkeeping across frames (what a capture file's frame list keeps
    // for the whole file): the reference frame, the previous frame, the
    // elapsed time, the byte count. Copies of frame_data are fine here --
    // only num and abs_ts are ever read back through them.
    frame_data ref_copy{};
    frame_data prev_copy{};
    const frame_data* ref = nullptr;
    const frame_data* prev = nullptr;
    nstime_t elapsed{};
    uint32_t cum_bytes = 0;

    Impl() {
        session = SharedEpan::Get().Acquire();
        if (!session) { SharedEpan::Get().Release(); throw std::runtime_error("epan_new failed"); }
        // Wireshark's own summary columns, from the profile's column list
        // that epan_load_settings() left in `prefs`.
        if (prefs.num_cols > 0) {
            col_setup(&cinfo, prefs.num_cols);
            build_column_format_array(&cinfo, prefs.num_cols, true);
            cinfo.epan = session;   // set_rel_time() resolves the reference through it
            have_columns = true;
        }
        nstime_set_zero(&elapsed);
    }
    ~Impl() {
        if (df) dfilter_free(df);
        if (have_columns) col_cleanup(&cinfo);
        if (session) SharedEpan::Get().Release();
    }
    void reset_time() {
        ref = nullptr;
        prev = nullptr;
        nstime_set_zero(&elapsed);
        cum_bytes = 0;
        ts.clear();
    }
};

DecodeSession::DecodeSession() : impl_(std::make_unique<Impl>()) {}
DecodeSession::~DecodeSession() = default;

void DecodeSession::reset() {
    frame_count_ = 0;
    impl_->reset_time();
}

bool DecodeSession::set_filter(std::string_view text, std::string& error) {
    error.clear();
    if (text.empty()) {
        if (impl_->df) dfilter_free(impl_->df);
        impl_->df = nullptr;
        filter_text_.clear();
        return true;
    }
    dfilter_t* df = nullptr;
    df_error_t* derr = nullptr;
    const std::string t(text);
    if (!dfilter_compile(t.c_str(), &df, &derr)) {
        error = (derr && derr->msg) ? derr->msg : "invalid display filter";
        if (derr) df_error_free(&derr);
        return false;
    }
    if (derr) df_error_free(&derr);
    if (impl_->df) dfilter_free(impl_->df);
    impl_->df = df;
    filter_text_ = t;
    return true;
}

std::vector<std::string> DecodeSession::column_titles() const {
    std::vector<std::string> out;
    if (!impl_->have_columns) return out;
    for (int i = 0; i < impl_->cinfo.num_cols; ++i) {
        const char* t = impl_->cinfo.columns[i].col_title;
        out.emplace_back(t ? t : "");
    }
    return out;
}

// Walk epan's proto_tree into our RenderNode shape.
static void walk_node(proto_node* node, RenderNode& out, int depth) {
    field_info* fi = PNODE_FINFO(node);
    if (fi) {
        if (fi->hfinfo && fi->hfinfo->abbrev) {
            out.name = fi->hfinfo->abbrev;
        }
        if (fi->rep) {
            // representation is a fixed-size char buffer; treat as C string.
            out.showname = fi->rep->representation;
        } else if (fi->hfinfo && (fi->hfinfo->display & BASE_NO_DISPLAY_VALUE) == 0) {
            // A field added to a visible tree without a representation (some
            // dissectors defer it): Wireshark's own label builder fills it.
            char label[ITEM_LABEL_LENGTH];
#if WIRESPY_WS_AT_LEAST(4, 6)
            // 4.6 grew a third argument, the offset of the value inside
            // the label; nullptr means "not wanted".
            proto_item_fill_label(fi, label, nullptr);
#else
            proto_item_fill_label(fi, label);
#endif
            out.showname = label;
        }
        out.pos = fi->start;
        out.size = fi->length;
        if (fi->ds_tvb && fi->start >= 0 && fi->length > 0 &&
            tvb_bytes_exist(fi->ds_tvb, fi->start, fi->length)) {
            const std::uint8_t* p = tvb_get_ptr(fi->ds_tvb, fi->start, fi->length);
            if (p) {
                static const char kHex[] = "0123456789abcdef";
                out.value.resize(static_cast<std::size_t>(fi->length) * 2);
                char* w = out.value.data();
                for (int i = 0; i < fi->length; ++i) {
                    *w++ = kHex[p[i] >> 4];
                    *w++ = kHex[p[i] & 15];
                }
            }
        }
    } else {
        // Root proto_tree has no field_info; name it "frame" for our wire
        // format. Callers may override this name.
        out.name = "frame";
    }
    // Wireshark caps its own tree depth (proto.c: MAX_TREE_LEVELS); a
    // matching cap here keeps a hostile frame from exhausting our stack.
    if (depth > 256) return;
    for (proto_node* c = node->first_child; c; c = c->next) {
        out.children.emplace_back();
        walk_node(c, out.children.back(), depth + 1);
    }
}

static std::string color_hex(const color_t& c) {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "#%02x%02x%02x",
                  (c.red >> 8) & 0xff, (c.green >> 8) & 0xff, (c.blue >> 8) & 0xff);
    return buf;
}

RenderNode DecodeSession::decode(std::span<const std::uint8_t> frame,
                                 int link_type_dlt) {
    DecodeRequest req;
    req.frame = frame;
    req.link_type_dlt = link_type_dlt;
    return decode(req).tree;
}

DecodeOutput DecodeSession::decode(const DecodeRequest& req) {
    if (req.link_type_dlt < 0) throw std::runtime_error("unknown link type");

    // epan's wtap_rec.pkt_encap is a WTAP_ENCAP_* value, not a libpcap DLT.
    const int wtap_encap = wtap_pcap_encap_to_wtap_encap(req.link_type_dlt);
    if (wtap_encap == WTAP_ENCAP_UNKNOWN) {
        throw std::runtime_error("unsupported link type DLT");
    }

    Impl& im = *impl_;
    DecodeOutput out;

    // Everything below is guarded so a throw (bad_alloc in the walk) still
    // tears the dissection down.
    struct Guard {
        wtap_rec rec{};
        frame_data fd{};
        epan_dissect_t* edt = nullptr;
        bool rec_init = false, fd_init = false;
        ~Guard() {
            if (edt) epan_dissect_free(edt);       // frees the tvb chain too
            if (fd_init) frame_data_destroy(&fd);
            if (rec_init) wtap_rec_cleanup(&rec);
        }
    } g;

    // Set up a wtap_rec describing the frame.
#if WIRESPY_WS_AT_LEAST(4, 5)
    wtap_rec_init(&g.rec, /*space=*/req.frame.size());
    g.rec.rec_type_name = "Frame";  // dissect_record passes this to col_set_str;
                                    // must not be NULL or column-utils asserts.
#else
    wtap_rec_init(&g.rec);
#endif
    g.rec_init = true;
    g.rec.rec_type = REC_TYPE_PACKET;
    g.rec.presence_flags = req.has_ts ? WTAP_HAS_TS : 0;
    g.rec.ts.secs = req.has_ts ? static_cast<time_t>(req.ts_sec) : 0;
    g.rec.ts.nsecs = req.has_ts ? req.ts_nsec : 0;
    g.rec.tsprec = WTAP_TSPREC_NSEC;
    g.rec.rec_header.packet_header.caplen = static_cast<uint32_t>(req.frame.size());
    g.rec.rec_header.packet_header.len = static_cast<uint32_t>(req.frame.size());
    g.rec.rec_header.packet_header.pkt_encap = wtap_encap;
    g.rec.rec_header.packet_header.interface_id = 0;

    // A transient decode saves the sequence state and restores it on the
    // way out, whatever happens in between.
    struct Saved {
        Impl& im;
        int& count;
        const bool active;
        const int saved_count;
        const std::size_t saved_ts;
        const frame_data ref_copy, prev_copy;
        const frame_data* const ref;
        const frame_data* const prev;
        const nstime_t elapsed;
        const uint32_t cum_bytes;
        Saved(Impl& i, int& c, bool on)
            : im(i), count(c), active(on), saved_count(c), saved_ts(i.ts.size()),
              ref_copy(i.ref_copy), prev_copy(i.prev_copy), ref(i.ref), prev(i.prev),
              elapsed(i.elapsed), cum_bytes(i.cum_bytes) {}
        ~Saved() {
            if (!active) return;
            count = saved_count;
            im.ts.resize(saved_ts);
            im.ref_copy = ref_copy;
            im.prev_copy = prev_copy;
            im.ref = (ref == nullptr) ? nullptr : &im.ref_copy;
            im.prev = (prev == nullptr) ? nullptr : &im.prev_copy;
            im.elapsed = elapsed;
            im.cum_bytes = cum_bytes;
        }
    } saved(im, frame_count_, req.transient);

    // Frame numbering + the timestamp table the provider answers from.
    uint32_t num;
    nstime_t ts;
    ts.secs = g.rec.ts.secs;
    ts.nsecs = g.rec.ts.nsecs;
    if (req.transient) {
        num = req.frame_number ? req.frame_number : static_cast<uint32_t>(frame_count_ + 1);
        if (im.ts.size() < num) im.ts.resize(num, ts);
        im.ts[num - 1] = ts;
        if (req.has_ref) {
            // The reference frame the in-order pass had: frame 1 by number
            // (what Wireshark shows without a user-set time reference).
            std::memset(&im.ref_copy, 0, sizeof im.ref_copy);
            im.ref_copy.num = 1;
            im.ref_copy.abs_ts.secs = static_cast<time_t>(req.ref_ts_sec);
            im.ref_copy.abs_ts.nsecs = req.ref_ts_nsec;
            im.ref_copy.has_ts = 1;
            im.ref = (num == 1) ? nullptr : &im.ref_copy;
            if (im.ts.size() < 1) im.ts.resize(1, ts);
            im.ts[0] = im.ref_copy.abs_ts;
        } else {
            im.ref = nullptr;
        }
        if (req.has_prev && num > 1) {
            std::memset(&im.prev_copy, 0, sizeof im.prev_copy);
            im.prev_copy.num = num - 1;
            im.prev_copy.abs_ts.secs = static_cast<time_t>(req.prev_ts_sec);
            im.prev_copy.abs_ts.nsecs = req.prev_ts_nsec;
            im.prev_copy.has_ts = 1;
            im.prev = &im.prev_copy;
            if (im.ts.size() >= num - 1) im.ts[num - 2] = im.prev_copy.abs_ts;
        } else {
            im.prev = nullptr;
        }
        nstime_set_zero(&im.elapsed);
    } else {
        num = static_cast<uint32_t>(++frame_count_);
        im.ts.push_back(ts);
    }
    out.frame_number = num;

    SharedEpan::Get().prov.ts = &im.ts;   // the provider answers from THIS session while it runs
    frame_data_init(&g.fd, num, &g.rec, /*offset=*/0, im.cum_bytes);
    g.fd_init = true;
    frame_data_set_before_dissect(&g.fd, &im.elapsed, &im.ref, im.prev);
    // frame_data_set_before_dissect points the reference at THIS frame when
    // there was none; keep a copy that outlives the dissection.
    const bool this_is_ref = (im.ref == &g.fd);

    // Run all dissectors. A visible tree fills in every field's text;
    // an invisible one only keeps the fields something asked for (the
    // display filter, the colouring rules) -- much cheaper for a
    // columns-only pass over a whole capture.
    g.edt = epan_dissect_new(im.session, /*create_proto_tree=*/true,
                             /*proto_tree_visible=*/req.want_tree);
    if (im.df) epan_dissect_prime_with_dfilter(g.edt, im.df);
    if (req.want_color) color_filters_prime_edt(g.edt);

    column_info* cinfo = (req.want_columns && im.have_columns) ? &im.cinfo : nullptr;
    if (cinfo) col_custom_prime_edt(g.edt, cinfo);

#if WIRESPY_WS_AT_LEAST(4, 5)
    // dissect_record builds its tvb from rec->data (a wsutil Buffer).
    ws_buffer_append(&g.rec.data, const_cast<std::uint8_t*>(req.frame.data()),
                     req.frame.size());
    epan_dissect_run(g.edt, /*file_type_subtype=*/-1, &g.rec, &g.fd, cinfo);
#else
    // 4.4: the caller owns the tvb; epan frees the chain with the edt.
    tvbuff_t* tvb = tvb_new_real_data(req.frame.data(),
                                      static_cast<unsigned>(req.frame.size()),
                                      static_cast<int>(req.frame.size()));
    epan_dissect_run(g.edt, /*file_type_subtype=*/-1, &g.rec, tvb, &g.fd, cinfo);
#endif

    if (cinfo) {
        epan_dissect_fill_in_columns(g.edt, /*fill_col_exprs=*/false, /*fill_fd_colums=*/true);
        out.columns.reserve(static_cast<std::size_t>(cinfo->num_cols));
        for (int i = 0; i < cinfo->num_cols; ++i) {
            const char* text = cinfo->columns[i].col_data;
            out.columns.emplace_back(text ? text : "");
        }
    }

    if (im.df) out.filter_matched = dfilter_apply_edt(im.df, g.edt);

    if (req.want_color) {
        if (const color_filter_t* cf = color_filters_colorize_packet(g.edt)) {
            out.color_name = cf->filter_name ? cf->filter_name : "";
            out.color_fg = color_hex(cf->fg_color);
            out.color_bg = color_hex(cf->bg_color);
        }
    }

    if (req.want_tree) {
        walk_node(g.edt->tree, out.tree, 0);
    }
    if (out.tree.name.empty()) out.tree.name = "frame";

    frame_data_set_after_dissect(&g.fd, &im.cum_bytes);

    // Persist what the next frame's timing needs before the guard tears
    // this frame_data down (only num / abs_ts are ever read back). A
    // transient decode's Saved guard puts the sequence state back instead.
    if (!req.transient) {
        if (this_is_ref) {
            im.ref_copy = g.fd;
            im.ref = &im.ref_copy;
        }
        im.prev_copy = g.fd;
        im.prev = &im.prev_copy;
    } else if (this_is_ref) {
        im.ref = nullptr;   // never leave a pointer at the dying frame_data
    }

    return out;
}

} // namespace wirespy
