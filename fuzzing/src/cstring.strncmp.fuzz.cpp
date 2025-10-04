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

[[nodiscard]] static auto fuzz_strncmp(FuzzedDataProvider& p) -> int
{
    auto const lhs   = p.ConsumeRandomLengthString();
    auto const rhs   = p.ConsumeRandomLengthString();
    auto const count = std::min(lhs.size(), rhs.size());

    auto const s  = std::strncmp(lhs.c_str(), rhs.c_str(), count);
    auto const e  = etl::strncmp(lhs.c_str(), rhs.c_str(), count);
    auto const ef = etl::detail::strncmp<char, etl::size_t, unsigned char>(lhs.c_str(), rhs.c_str(), count);

    if ((sign(e) != sign(s)) or (sign(ef) != sign(s))) {
        std::println(stderr, "strncmp('{}', '{}')", lhs, rhs);
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
    RUN(fuzz_strncmp(p));
    return 0;
}
