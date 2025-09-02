// SPDX-License-Identifier: BSL-1.0

#pragma once

#include "fuzzer/FuzzedDataProvider.h"

#include <etl/charconv.hpp>
#include <etl/system_error.hpp>

#include <charconv>
#include <map>
#include <print>
#include <stdexcept>
#include <string>
#include <system_error>

#define RUN(func)                                                                                                      \
    do {                                                                                                               \
        if (auto rc = func; rc != 0) {                                                                                 \
            throw rc;                                                                                                  \
        }                                                                                                              \
    } while (false)

namespace etl::fuzzing {

auto to_string(std::errc ec) -> std::string
{
    static auto map = std::map<std::errc, std::string>{
        {                   std::errc{},              "errc{}"},
        {   std::errc::invalid_argument,    "invalid_argument"},
        {std::errc::result_out_of_range, "result_out_of_range"},
        {    std::errc::value_too_large,     "value_too_large"},
    };

    return map.at(ec);
}

auto to_std(etl::errc ec) -> std::errc
{
    static auto map = std::map<etl::errc, std::errc>{
        {                   etl::errc{},                    std::errc{}},
        {   etl::errc::invalid_argument,    std::errc::invalid_argument},
        {etl::errc::result_out_of_range, std::errc::result_out_of_range},
        {    etl::errc::value_too_large,     std::errc::value_too_large},
    };

    return map.at(ec);
}
auto to_std(etl::from_chars_result r) -> std::from_chars_result { return {.ptr = r.ptr, .ec = to_std(r.ec)}; }
auto to_std(etl::to_chars_result r) -> std::to_chars_result { return {.ptr = r.ptr, .ec = to_std(r.ec)}; }

} // namespace etl::fuzzing
