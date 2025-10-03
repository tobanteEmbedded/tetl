// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/algorithm.hpp>
#include <etl/cstdint.hpp>
#include <etl/limits.hpp>
#include <etl/string_view.hpp>

#include <algorithm>
#include <print>

[[nodiscard]] static auto fuzz_reverse(FuzzedDataProvider& p) -> int
{
    auto const str  = p.ConsumeRandomLengthString(32);
    auto const view = etl::string_view{str.data(), str.size()};

    auto const e = etl::is_partitioned(view.begin(), view.end(), [](char c) { return c < 'a'; });
    auto const s = std::is_partitioned(view.begin(), view.end(), [](char c) { return c < 'a'; });

    if (e != s) {
        std::println(stderr, "is_partitioned: '{}'", str);
        std::println(stderr, "etl: '{}'", e);
        std::println(stderr, "std: '{}'", s);
        return 1;
    }

    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_reverse(p));
    return 0;
}
