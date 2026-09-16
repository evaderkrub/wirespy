// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Dave Robins

#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>
#include <nlohmann/json.hpp>

namespace wirespy {

struct ParsedRequest {
    nlohmann::json header;
    std::span<const std::uint8_t> frame; // view into caller's buffer
};

enum class ParseError {
    TRUNCATED,         // not enough bytes for the framing
    JSON_LEN_TOO_BIG,  // json_len > body length - 4
    BAD_JSON,          // header is not valid JSON
};

// Parse a TCP request body. `body` is the bytes AFTER total_len was consumed.
// On success returns ParsedRequest whose `frame` views into `body`.
std::variant<ParsedRequest, ParseError>
parse_request_body(std::span<const std::uint8_t> body);

// Serialize a response. Returns a buffer containing [total_len:u32 BE][json bytes].
std::vector<std::uint8_t> serialize_response(const nlohmann::json& response);

enum class ErrorCode {
    BAD_REQUEST,
    BAD_FRAME,
    UNKNOWN_LINK_TYPE,
    BAD_FILTER,
    INTERNAL,
};

const char* error_code_name(ErrorCode c);

nlohmann::json make_error_response(int id, ErrorCode code, std::string_view message);

} // namespace wirespy
