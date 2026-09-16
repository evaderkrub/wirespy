// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Dave Robins

#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <nlohmann/json.hpp>

namespace wirespy {

struct RenderNode {
    std::string name;     // e.g. "ip.src"
    std::string showname; // e.g. "Source: 10.0.0.1"
    std::string value;    // hex string of raw bytes, e.g. "0a000001"
    int pos = 0;
    int size = 0;
    std::vector<RenderNode> children;
};

nlohmann::json render_json(const RenderNode& root);

// Render the same tree as one line per node, indented by depth.
std::string render_text(const RenderNode& root);

} // namespace wirespy
