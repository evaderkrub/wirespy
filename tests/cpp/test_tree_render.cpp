// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Dave Robins

#include <catch2/catch_test_macros.hpp>
#include "tree_render.hpp"
using namespace wirespy;

TEST_CASE("render_json - single node, no children") {
    RenderNode n{"frame", "Frame 1", "", 0, 60, {}};
    auto j = render_json(n);
    REQUIRE(j["name"] == "frame");
    REQUIRE(j["showname"] == "Frame 1");
    REQUIRE(j["pos"] == 0);
    REQUIRE(j["size"] == 60);
    REQUIRE(j["children"].is_array());
    REQUIRE(j["children"].empty());
}

TEST_CASE("render_json - nested children") {
    RenderNode child{"ip.src", "Source: 10.0.0.1", "0a000001", 26, 4, {}};
    RenderNode root{"frame", "Frame 1", "", 0, 60, {child}};
    auto j = render_json(root);
    REQUIRE(j["children"].size() == 1);
    REQUIRE(j["children"][0]["name"] == "ip.src");
    REQUIRE(j["children"][0]["value"] == "0a000001");
}

TEST_CASE("render_text - indented lines") {
    RenderNode child{"ip.src", "Source: 10.0.0.1", "", 26, 4, {}};
    RenderNode root{"frame", "Frame 1", "", 0, 60, {child}};
    auto text = render_text(root);
    REQUIRE(text == "Frame 1\n  Source: 10.0.0.1\n");
}
