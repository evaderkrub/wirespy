// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Dave Robins

// src/server/tree_render.cpp
#include "tree_render.hpp"

namespace wirespy {

nlohmann::json render_json(const RenderNode& node) {
    nlohmann::json out = {
        {"name", node.name},
        {"showname", node.showname},
        {"value", node.value},
        {"pos", node.pos},
        {"size", node.size},
        {"children", nlohmann::json::array()},
    };
    for (const auto& c : node.children) {
        out["children"].push_back(render_json(c));
    }
    return out;
}

static void render_text_into(const RenderNode& n, int depth, std::string& out) {
    for (int i = 0; i < depth * 2; ++i) out.push_back(' ');
    out += n.showname.empty() ? n.name : n.showname;
    out.push_back('\n');
    for (auto& c : n.children) render_text_into(c, depth + 1, out);
}

std::string render_text(const RenderNode& root) {
    std::string out;
    render_text_into(root, 0, out);
    return out;
}

} // namespace wirespy
