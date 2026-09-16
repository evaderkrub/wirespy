// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Dave Robins

// src/server/main.cpp -- wirespy_server: libwireshark behind a tiny
// length-prefixed TCP protocol (see docs/PROTOCOL.md).
//
//   wirespy_server [--port N] [--parent-pid PID] [--data-dir DIR]
//
// --port 0 asks the OS for a free port; whichever port was bound is
// announced on stdout as "wirespy listening on tcp/<port>" so a parent that
// spawned us can read it back. --parent-pid makes the server exit when that
// process is gone (a GUI that spawned it and crashed).
#include "decode_session.hpp"
#include "epan_runtime.hpp"
#include "tcp_listener.hpp"
#include "tree_render.hpp"
#include "wire_protocol.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#include <unistd.h>
#endif

#include <nlohmann/json.hpp>

using namespace wirespy;

namespace {

// The link type may come as a name ("EN10MB") or as the DLT number itself.
int link_type_of(const nlohmann::json& header) {
    auto it = header.find("link_type");
    if (it == header.end()) return dlt_from_name("EN10MB");
    if (it->is_number_integer()) return it->get<int>();
    if (it->is_string()) return dlt_from_name(it->get_ref<const std::string&>());
    return -1;
}

int id_of(const nlohmann::json& header) {
    auto it = header.find("id");
    return (it != header.end() && it->is_number_integer()) ? it->get<int>() : -1;
}

template <class T>
T field_or(const nlohmann::json& header, const char* key, T dflt) {
    auto it = header.find(key);
    if (it == header.end()) return dflt;
    try { return it->get<T>(); } catch (...) { return dflt; }
}

std::vector<std::uint8_t> handle_decode(DecodeSession& session, int id,
                                        const ParsedRequest& req) {
    const int dlt = link_type_of(req.header);
    if (dlt < 0) {
        return serialize_response(make_error_response(
            id, ErrorCode::UNKNOWN_LINK_TYPE, field_or<std::string>(req.header, "link_type", "?")));
    }
    const std::string fmt = field_or<std::string>(req.header, "format", "json");

    DecodeRequest dr;
    dr.frame = req.frame;
    dr.link_type_dlt = dlt;
    if (req.header.contains("ts_sec")) {
        dr.has_ts = true;
        dr.ts_sec = field_or<std::int64_t>(req.header, "ts_sec", 0);
        dr.ts_nsec = field_or<std::int32_t>(req.header, "ts_nsec", 0);
    }
    dr.want_tree = fmt != "columns" && field_or<bool>(req.header, "tree", true);
    dr.transient = field_or<bool>(req.header, "transient", false);
    dr.frame_number = field_or<std::uint32_t>(req.header, "frame_number", 0u);
    if (req.header.contains("ref_ts_sec")) {
        dr.has_ref = true;
        dr.ref_ts_sec = field_or<std::int64_t>(req.header, "ref_ts_sec", 0);
        dr.ref_ts_nsec = field_or<std::int32_t>(req.header, "ref_ts_nsec", 0);
    }
    if (req.header.contains("prev_ts_sec")) {
        dr.has_prev = true;
        dr.prev_ts_sec = field_or<std::int64_t>(req.header, "prev_ts_sec", 0);
        dr.prev_ts_nsec = field_or<std::int32_t>(req.header, "prev_ts_nsec", 0);
    }
    dr.want_columns = field_or<bool>(req.header, "columns", fmt == "columns");
    dr.want_color = field_or<bool>(req.header, "color", false);

    try {
        DecodeOutput out = session.decode(dr);
        nlohmann::json resp = {
            {"id", id},
            {"ok", true},
            {"frame_number", out.frame_number},
            {"format", fmt},
            {"match", out.filter_matched},
        };
        if (dr.want_tree) {
            if (fmt == "text") resp["decode"] = render_text(out.tree);
            else resp["decode"] = render_json(out.tree);
        }
        if (dr.want_columns) resp["columns"] = out.columns;
        if (dr.want_color && !out.color_bg.empty()) {
            resp["color"] = {{"name", out.color_name}, {"fg", out.color_fg}, {"bg", out.color_bg}};
        }
        return serialize_response(resp);
    } catch (std::exception const& e) {
        return serialize_response(make_error_response(id, ErrorCode::BAD_FRAME, e.what()));
    }
}

// libwireshark is single-threaded: its dissector tables, the column and
// colouring state and the display-filter engine are process globals. One
// connection per thread is fine for the SOCKET work, but every dissection
// (and every filter compile) must take its turn here -- two sessions
// dissecting at once corrupt each other and take the process down.
std::mutex g_epan_mutex;

std::vector<std::uint8_t> handle_message(DecodeSession& session, const EpanRuntime& rt,
                                         std::span<const std::uint8_t> body) {
    std::lock_guard<std::mutex> epan_turn(g_epan_mutex);
    auto parsed = parse_request_body(body);
    if (std::holds_alternative<ParseError>(parsed)) {
        return serialize_response(
            make_error_response(-1, ErrorCode::BAD_REQUEST, "could not parse request"));
    }
    auto& req = std::get<ParsedRequest>(parsed);
    const int id = id_of(req.header);
    const std::string op = field_or<std::string>(req.header, "op", "decode");

    if (op == "decode") return handle_decode(session, id, req);

    if (op == "set_filter") {
        const std::string text = field_or<std::string>(req.header, "filter", "");
        std::string err;
        if (!session.set_filter(text, err)) {
            return serialize_response(make_error_response(id, ErrorCode::BAD_FILTER, err));
        }
        return serialize_response({{"id", id}, {"ok", true}, {"filter", session.filter()}});
    }
    if (op == "reset") {
        session.reset();
        return serialize_response({{"id", id}, {"ok", true}});
    }
    if (op == "info") {
        return serialize_response({
            {"id", id},
            {"ok", true},
            {"server", "wirespy"},
            {"wireshark", rt.version() ? rt.version() : ""},
            {"columns", session.column_titles()},
            {"link_types", known_link_types()},
            {"colors", rt.colors_loaded()},
            {"filter", session.filter()},
        });
    }
    return serialize_response(make_error_response(id, ErrorCode::BAD_REQUEST, "unknown op: " + op));
}

// Exit when the process that spawned us is gone.
void watch_parent(long pid) {
#ifdef _WIN32
    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, static_cast<DWORD>(pid));
    if (!h) { std::_Exit(0); }
    WaitForSingleObject(h, INFINITE);
    std::_Exit(0);
#else
    while (true) {
        if (::kill(static_cast<pid_t>(pid), 0) != 0 || ::getppid() == 1) std::_Exit(0);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
#endif
}

} // namespace

int main(int argc, char** argv) {
    int port = 51717;
    long parent = 0;
    std::string data_dir;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--port" && i + 1 < argc) port = std::atoi(argv[++i]);
        else if (a == "--parent-pid" && i + 1 < argc) parent = std::atol(argv[++i]);
        else if (a == "--data-dir" && i + 1 < argc) data_dir = argv[++i];
        else if (a == "--help" || a == "-h") {
            std::printf("usage: wirespy_server [--port N] [--parent-pid PID] [--data-dir DIR]\n");
            return 0;
        }
    }

    try {
        EpanRuntime epan(argv[0], data_dir.empty() ? nullptr : data_dir.c_str());
        const EpanRuntime* rt = &epan;
        TcpListener listener(static_cast<std::uint16_t>(port), [rt]() {
            // One DecodeSession per connection -- captured by the handler.
            auto session = std::make_shared<DecodeSession>();
            return [session, rt](std::span<const std::uint8_t> body) {
                return handle_message(*session, *rt, body);
            };
        });
        const std::uint16_t bound = listener.listen();
        std::printf("wirespy listening on tcp/%u\n", static_cast<unsigned>(bound));
        std::fflush(stdout);
        if (parent > 0) std::thread(watch_parent, parent).detach();
        listener.run();
    } catch (std::exception const& e) {
        std::fprintf(stderr, "fatal: %s\n", e.what());
        return 1;
    }
    return 0;
}
