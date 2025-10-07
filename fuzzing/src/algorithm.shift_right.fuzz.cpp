// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/algorithm.hpp>
#include <etl/cstdint.hpp>
#include <etl/limits.hpp>
#include <etl/span.hpp>

#include <algorithm>
#include <print>

[[nodiscard]] static auto fuzz_shift_right(FuzzedDataProvider& p) -> int
{
    auto shift  = p.ConsumeIntegralInRange<etl::ptrdiff_t>(0, etl::numeric_limits<etl::ptrdiff_t>::max());
    auto ebytes = p.ConsumeRemainingBytes<unsigned char>();
    auto sbytes = ebytes;

    auto const eview = etl::span<unsigned char>{ebytes.data(), ebytes.size()};
    auto const sview = etl::span<unsigned char>{sbytes.data(), sbytes.size()};

    auto const e = etl::shift_right(eview.begin(), eview.end(), shift);
    auto const s = std::shift_right(sview.begin(), sview.end(), shift);

    auto const ed = std::distance(eview.begin(), e);
    auto const sd = std::distance(sview.begin(), s);
    if ((ed != sd) or not std::equal(e, eview.end(), s, sview.end())) {
        std::println(stderr, "size: {}, shift: {}, s: {}, e: {}", eview.size(), shift, sd, ed);
        return 1;
    }

    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_shift_right(p));
    return 0;
}
