// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/cstring.hpp>

#include <cstring>
#include <print>

[[nodiscard]] static auto fuzz_strlen(FuzzedDataProvider& p) -> int
{
    auto const str = p.ConsumeRandomLengthString();

    auto const s  = std::strlen(str.c_str());
    auto const e  = etl::strlen(str.c_str());
    auto const ef = etl::detail::strlen<char, etl::size_t>(str.c_str());

    if ((e != s) or (ef != s)) {
        std::println(stderr, "strlen(\"{}\")", str);
        std::println(stderr, "std = {}", s);
        std::println(stderr, "etl = {}", e);
        std::println(stderr, "etl::detail = {}", ef);
        return 1;
    }

    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_strlen(p));
    return 0;
}
