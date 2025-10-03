// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/algorithm.hpp>
#include <etl/cstdint.hpp>
#include <etl/limits.hpp>
#include <etl/span.hpp>

#include <algorithm>
#include <print>

[[nodiscard]] auto fuzz_reverse(FuzzedDataProvider& p) -> int
{
    auto const str = p.ConsumeRandomLengthString(16);

    auto estr = str;
    auto sstr = str;

    auto const e = etl::span<char>{estr.data(), estr.size()};
    auto const s = etl::span<char>{sstr.data(), sstr.size()};

    etl::reverse(e.begin(), e.end());
    std::reverse(s.begin(), s.end());

    if (estr != sstr) {
        std::println(stderr, "reverse: '{}'", str);
        std::println(stderr, "std: '{}'", sstr);
        std::println(stderr, "etl: '{}'", estr);
        return 1;
    }

    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(etl::uint8_t const* data, etl::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_reverse(p));
    return 0;
}
