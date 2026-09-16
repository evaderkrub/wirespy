// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Dave Robins

// tests/cpp/test_smoke.cpp
#include <catch2/catch_test_macros.hpp>

TEST_CASE("catch2 wired up") {
    REQUIRE(1 + 1 == 2);
}
