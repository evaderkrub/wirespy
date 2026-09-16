// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Dave Robins

#include <catch2/catch_test_macros.hpp>
#include <vector>
#include "wire_protocol.hpp"

using namespace wirespy;

namespace {
// Build a body: [json_len:u32 BE][json bytes][frame bytes]
std::vector<std::uint8_t> make_body(const std::string& json,
                                    std::span<const std::uint8_t> frame) {
    std::vector<std::uint8_t> out;
    auto jl = static_cast<std::uint32_t>(json.size());
    out.push_back((jl >> 24) & 0xff);
    out.push_back((jl >> 16) & 0xff);
    out.push_back((jl >> 8) & 0xff);
    out.push_back(jl & 0xff);
    out.insert(out.end(), json.begin(), json.end());
    out.insert(out.end(), frame.begin(), frame.end());
    return out;
}
}

TEST_CASE("parse_request_body - happy path") {
    std::string json = R"({"op":"decode","id":1})";
    std::vector<std::uint8_t> frame = {0xaa, 0xbb, 0xcc};
    auto body = make_body(json, frame);

    auto result = parse_request_body(body);
    auto* ok = std::get_if<ParsedRequest>(&result);
    REQUIRE(ok != nullptr);
    REQUIRE(ok->header["op"] == "decode");
    REQUIRE(ok->header["id"] == 1);
    REQUIRE(ok->frame.size() == 3);
    REQUIRE(ok->frame[0] == 0xaa);
}

TEST_CASE("parse_request_body - body shorter than 4 bytes") {
    std::vector<std::uint8_t> body = {0x00, 0x01};
    auto result = parse_request_body(body);
    REQUIRE(std::get<ParseError>(result) == ParseError::TRUNCATED);
}

TEST_CASE("parse_request_body - json_len larger than body") {
    std::vector<std::uint8_t> body = {0x00, 0x00, 0xff, 0xff, 'x'};
    auto result = parse_request_body(body);
    REQUIRE(std::get<ParseError>(result) == ParseError::JSON_LEN_TOO_BIG);
}

TEST_CASE("parse_request_body - invalid json") {
    std::string bad = "{not json";
    std::vector<std::uint8_t> frame;
    auto body = make_body(bad, frame);
    auto result = parse_request_body(body);
    REQUIRE(std::get<ParseError>(result) == ParseError::BAD_JSON);
}

TEST_CASE("parse_request_body - empty frame allowed") {
    std::string json = R"({"op":"decode","id":2})";
    std::vector<std::uint8_t> frame_bytes;
    auto body = make_body(json, frame_bytes);
    auto result = parse_request_body(body);
    auto* ok = std::get_if<ParsedRequest>(&result);
    REQUIRE(ok != nullptr);
    REQUIRE(ok->frame.empty());
}

TEST_CASE("serialize_response - round-trips through total_len") {
    nlohmann::json resp = {{"id", 1}, {"ok", true}};
    auto bytes = serialize_response(resp);

    REQUIRE(bytes.size() >= 4);
    std::uint32_t total_len =
        (std::uint32_t(bytes[0]) << 24) |
        (std::uint32_t(bytes[1]) << 16) |
        (std::uint32_t(bytes[2]) << 8) |
        std::uint32_t(bytes[3]);
    REQUIRE(total_len == bytes.size() - 4);

    auto json_text = std::string(bytes.begin() + 4, bytes.end());
    auto parsed = nlohmann::json::parse(json_text);
    REQUIRE(parsed["id"] == 1);
    REQUIRE(parsed["ok"] == true);
}

TEST_CASE("make_error_response - shape matches spec") {
    auto r = make_error_response(42, ErrorCode::BAD_FRAME, "truncated");
    REQUIRE(r["id"] == 42);
    REQUIRE(r["ok"] == false);
    REQUIRE(r["error"]["code"] == "BAD_FRAME");
    REQUIRE(r["error"]["message"] == "truncated");
}

TEST_CASE("error_code_name - covers every code") {
    REQUIRE(std::string(error_code_name(ErrorCode::BAD_REQUEST)) == "BAD_REQUEST");
    REQUIRE(std::string(error_code_name(ErrorCode::BAD_FRAME)) == "BAD_FRAME");
    REQUIRE(std::string(error_code_name(ErrorCode::UNKNOWN_LINK_TYPE)) == "UNKNOWN_LINK_TYPE");
    REQUIRE(std::string(error_code_name(ErrorCode::INTERNAL)) == "INTERNAL");
}
