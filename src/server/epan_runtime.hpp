// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Dave Robins

// src/server/epan_runtime.hpp
#pragma once

namespace wirespy {

// RAII handle: constructing it runs the full libwireshark init sequence,
// destroying it tears it down. Must be constructed exactly once per
// process. Throws on init failure.
class EpanRuntime {
public:
    // argv0 is needed by configuration_init() to locate plugin/prefs paths
    // from the running executable's directory. data_dir (optional) is
    // exported as WIRESHARK_DATA_DIR before init so the colouring rules,
    // display-filter macros and the like are found under a no-root prefix
    // (the CMake-configured WIRESPY_DATA_DIR is the fallback).
    explicit EpanRuntime(const char* argv0, const char* data_dir = nullptr);
    ~EpanRuntime();
    EpanRuntime(const EpanRuntime&) = delete;
    EpanRuntime& operator=(const EpanRuntime&) = delete;

    // True when Wireshark's colouring rules loaded (a colorfilters file was
    // found). Without them every packet comes back uncoloured.
    bool colors_loaded() const { return colors_; }
    const char* version() const;

private:
    bool colors_ = false;
};

} // namespace wirespy
