// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/cstring.hpp>

#include <algorithm>
#include <cstring>
#include <print>

[[nodiscard]] static constexpr auto sign(int x) -> int
{
    if (x > 0) {
        return 1;
    }
    if (x < 0) {
        return -1;
    }
    return 0;
}

[[nodiscard]] static auto fuzz_strcmp(FuzzedDataProvider& p) -> int
{
    auto const lhs = p.ConsumeRandomLengthString();
    auto const rhs = p.ConsumeRandomLengthString();

    auto const s  = std::strcmp(lhs.c_str(), rhs.c_str());
    auto const e  = etl::strcmp(lhs.c_str(), rhs.c_str());
    auto const ef = etl::detail::strcmp<char, unsigned char>(lhs.c_str(), rhs.c_str());

    if ((sign(e) != sign(s)) or (sign(ef) != sign(s))) {
        std::println(stderr, "strcmp('{}', '{}')", lhs, rhs);
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
    RUN(fuzz_strcmp(p));
    return 0;
}
