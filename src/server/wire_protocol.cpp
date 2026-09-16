// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Dave Robins

#include "wire_protocol.hpp"
#include <stdexcept>

namespace wirespy {

static std::uint32_t read_u32_be(const std::uint8_t* p) {
    return (std::uint32_t(p[0]) << 24)
         | (std::uint32_t(p[1]) << 16)
         | (std::uint32_t(p[2]) << 8)
         | (std::uint32_t(p[3]));
}

std::variant<ParsedRequest, ParseError>
parse_request_body(std::span<const std::uint8_t> body) {
    if (body.size() < 4) return ParseError::TRUNCATED;
    auto json_len = read_u32_be(body.data());
    if (json_len > body.size() - 4) return ParseError::JSON_LEN_TOO_BIG;

    auto json_start = body.data() + 4;
    auto frame_start = json_start + json_len;
    auto frame_size = body.size() - 4 - json_len;

    nlohmann::json header;
    try {
        header = nlohmann::json::parse(json_start, json_start + json_len);
    } catch (const nlohmann::json::parse_error&) {
        return ParseError::BAD_JSON;
    }

    return ParsedRequest{
        std::move(header),
        std::span<const std::uint8_t>(frame_start, frame_size)
    };
}

static void write_u32_be(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back((v >> 24) & 0xff);
    out.push_back((v >> 16) & 0xff);
    out.push_back((v >> 8) & 0xff);
    out.push_back(v & 0xff);
}

std::vector<std::uint8_t> serialize_response(const nlohmann::json& response) {
    auto json_text = response.dump();
    std::vector<std::uint8_t> out;
    out.reserve(4 + json_text.size());
    write_u32_be(out, static_cast<std::uint32_t>(json_text.size()));
    out.insert(out.end(), json_text.begin(), json_text.end());
    return out;
}

const char* error_code_name(ErrorCode c) {
    switch (c) {
        case ErrorCode::BAD_REQUEST: return "BAD_REQUEST";
        case ErrorCode::BAD_FRAME: return "BAD_FRAME";
        case ErrorCode::UNKNOWN_LINK_TYPE: return "UNKNOWN_LINK_TYPE";
        case ErrorCode::BAD_FILTER: return "BAD_FILTER";
        case ErrorCode::INTERNAL: return "INTERNAL";
    }
    return "INTERNAL";
}

nlohmann::json make_error_response(int id, ErrorCode code, std::string_view message) {
    return {
        {"id", id},
        {"ok", false},
        {"error", {{"code", error_code_name(code)}, {"message", std::string(message)}}}
    };
}

} // namespace wirespy
