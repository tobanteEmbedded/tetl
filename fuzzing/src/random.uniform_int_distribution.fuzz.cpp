// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/random.hpp>
#include <etl/utility.hpp>

#include <random>

template <typename Int>
[[nodiscard]] auto fuzz_uniform_int_distribution(FuzzedDataProvider& p) -> int
{
    static constexpr auto min = etl::numeric_limits<Int>::lowest();
    static constexpr auto max = etl::numeric_limits<Int>::max();

    auto const dist_min = p.ConsumeIntegralInRange<Int>(min, max);
    if (dist_min == max) {
        return 0;
    }

    auto const dist_max = p.ConsumeIntegralInRange<Int>(dist_min, max);
    if (dist_min == dist_max) {
        return 0;
    }

    auto urng = etl::xoshiro128plusplus{p.ConsumeIntegral<etl::uint32_t>()};
    auto dist = etl::uniform_int_distribution<Int>{dist_min, dist_max};

    auto const val = dist(urng);
    return (val < dist_min or val > dist_max) ? 1 : 0;
}

extern "C" auto LLVMFuzzerTestOneInput(etl::uint8_t const* data, etl::size_t size) -> int
{
    if (size == 0) {
        return 0;
    }

    auto p = FuzzedDataProvider{data, size};

    RUN(fuzz_uniform_int_distribution<signed short>(p));
    RUN(fuzz_uniform_int_distribution<signed int>(p));
    // RUN(fuzz_uniform_int_distribution<signed long>(p));
    // RUN(fuzz_uniform_int_distribution<signed long long>(p));

    RUN(fuzz_uniform_int_distribution<unsigned short>(p));
    RUN(fuzz_uniform_int_distribution<unsigned int>(p));
    // RUN(fuzz_uniform_int_distribution<unsigned long>(p));
    // RUN(fuzz_uniform_int_distribution<unsigned long long>(p));

    return 0;
}
