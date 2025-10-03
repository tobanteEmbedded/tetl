// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/cstring.hpp>

#include <algorithm>
#include <cstring>
#include <print>

[[nodiscard]] static auto fuzz_strstr(FuzzedDataProvider& p) -> int
{
    auto const haystack = p.ConsumeRandomLengthString(64);
    auto const needle   = p.ConsumeRandomLengthString(64);

    auto const s  = std::strstr(haystack.c_str(), needle.c_str());
    auto const e  = etl::strstr(haystack.c_str(), needle.c_str());
    auto const ef = etl::detail::strstr(haystack.c_str(), needle.c_str());

    if ((e != s) or (ef != s)) {
        std::println(stderr, "strstr('{}', '{}')", haystack, needle);
        if (s == nullptr) {
            std::println(stderr, "std = {}", s == nullptr);
            std::println(stderr, "etl = {}", e == nullptr);
            std::println(stderr, "etl::detail = {}", ef == nullptr);
        } else {
            std::println(stderr, "std = {}", s - haystack.c_str());
            std::println(stderr, "etl = {}", e - haystack.c_str());
            std::println(stderr, "etl::detail = {}", ef - haystack.c_str());
        }
        return 1;
    }

    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_strstr(p));
    return 0;
}
