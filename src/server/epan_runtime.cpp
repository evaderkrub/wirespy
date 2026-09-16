// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Dave Robins

// src/server/epan_runtime.cpp
#include "epan_runtime.hpp"
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>

// Wireshark headers handle their own extern "C" via __cplusplus guards.
// Do NOT wrap them in extern "C" here -- doing so drags C++ stdlib templates
// into C linkage and breaks the build.
#include <ws_version.h>
#include <epan/epan.h>
#include <epan/color_filters.h>
#include <epan/prefs.h>
#include <epan/timestamp.h>
#include <wiretap/wtap.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/wslog.h>

#include "ws_compat.hpp"

namespace wirespy {

EpanRuntime::EpanRuntime(const char* argv0, const char* data_dir) {
    if (!data_dir || !*data_dir) {
#ifdef WIRESPY_DATA_DIR
        data_dir = WIRESPY_DATA_DIR;
#endif
    }
    if (data_dir && *data_dir && !std::getenv("WIRESHARK_DATA_DIR")) {
#ifdef _WIN32
        _putenv_s("WIRESHARK_DATA_DIR", data_dir);
#else
        setenv("WIRESHARK_DATA_DIR", data_dir, 1);
#endif
    }
    // init_process_policies() FIRST: configuration_init() consults
    // started_with_special_privs() (the WIRESHARK_DATA_DIR override is only
    // honoured without special privileges) and that asserts otherwise.
    init_process_policies();
#if WIRESPY_WS_AT_LEAST(4, 5)
    ws_log_init(nullptr);
    char* err = configuration_init(argv0);
#else
    ws_log_init("wirespy", nullptr);
    char* err = configuration_init(argv0, nullptr);
#endif
    if (err != nullptr) {
        std::string msg = "configuration_init failed: ";
        msg += err;
        throw std::runtime_error(msg);
    }
    wtap_init(/*load_wiretap_plugins=*/false);
    if (!epan_init(nullptr, nullptr, /*load_plugins=*/false)) {
        throw std::runtime_error("epan_init failed");
    }
    // The global prefs (or the defaults): the column list, decode-as and the
    // disabled-protocol tables. Some dissectors assert on missing column
    // state without it. Process-global, so it lives here rather than in
    // every DecodeSession.
    (void)epan_load_settings();
    // The Time column's display format is process state a GUI normally sets
    // from its preferences; without it col_set_cls_time() asserts.
    timestamp_set_type(TS_RELATIVE);
    timestamp_set_precision(TS_PREC_AUTO);
    timestamp_set_seconds_type(TS_SECONDS_DEFAULT);
    // Wireshark's packet-list colouring rules ("colorfilters" in the data
    // dir; a personal profile's copy wins when present). A missing file is
    // not fatal: packets simply come back uncoloured.
    char* cerr = nullptr;
    colors_ = color_filters_init(&cerr, nullptr);
    if (!colors_) {
        std::fprintf(stderr, "wirespy: colouring rules not loaded: %s\n",
                     cerr ? cerr : "(no message)");
    }
    if (cerr) g_free(cerr);
}

EpanRuntime::~EpanRuntime() {
    color_filters_cleanup();
    epan_cleanup();
}

const char* EpanRuntime::version() const { return epan_get_version(); }

} // namespace wirespy
