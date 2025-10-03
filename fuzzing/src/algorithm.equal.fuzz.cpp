// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/algorithm.hpp>
#include <etl/string_view.hpp>

#include <algorithm>
#include <print>

template <typename IntType>
[[nodiscard]] static auto fuzz_equal(FuzzedDataProvider& p) -> int
{
    auto const a = p.ConsumeRandomLengthString(64);
    auto const b = p.ConsumeRandomLengthString(64);

    auto const av = etl::string_view{a.data(), a.size()};
    auto const bv = etl::string_view{b.data(), b.size()};

    auto const e = etl::equal(av.begin(), av.end(), bv.begin(), bv.end());
    auto const s = std::equal(av.begin(), av.end(), bv.begin(), bv.end());

    if (e != s) {
        std::println(stderr, "equal: '{}' vs. '{}'", a, b);
        std::println(stderr, "etl: {}", e);
        std::println(stderr, "std: {}", s);
        return 1;
    }

    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(etl::uint8_t const* data, etl::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_equal<int>(p));
    return 0;
}
