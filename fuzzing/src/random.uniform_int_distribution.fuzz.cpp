// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/cstdint.hpp>
#include <etl/limits.hpp>
#include <etl/random.hpp>

#include <print>
#include <random>
#include <utility>

template <typename Int>
[[nodiscard]] static auto fuzz_uniform_int_distribution(FuzzedDataProvider& p) -> int
{
    static constexpr auto min = etl::numeric_limits<Int>::min();
    static constexpr auto max = etl::numeric_limits<Int>::max();

    auto const distMin = p.ConsumeIntegralInRange<Int>(min, max);
    auto const distMax = p.ConsumeIntegralInRange<Int>(distMin, max);
    if (distMin == distMax) {
        return 0;
    }

    auto const seed = p.ConsumeIntegral<etl::uint32_t>();
    if (seed == 0) {
        return 0;
    }

    auto urng = etl::xoshiro128plusplus{seed};
    auto dist = etl::uniform_int_distribution<Int>{distMin, distMax};

    auto const val = dist(urng);
    if (std::cmp_less(val, distMin) or std::cmp_greater(val, distMax)) {
        std::println(stderr, "dist = uniform_int_distribution({}, {}) = {}", distMin, distMax, val);
        return 1;
    }
    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    if (size == 0) {
        return 0;
    }

    auto p = FuzzedDataProvider{data, size};

    RUN(fuzz_uniform_int_distribution<signed short>(p));
    // RUN(fuzz_uniform_int_distribution<signed int>(p));
    // RUN(fuzz_uniform_int_distribution<signed long>(p));
    // RUN(fuzz_uniform_int_distribution<signed long long>(p));

    // RUN(fuzz_uniform_int_distribution<unsigned short>(p));
    // RUN(fuzz_uniform_int_distribution<unsigned int>(p));
    // RUN(fuzz_uniform_int_distribution<unsigned long>(p));
    // RUN(fuzz_uniform_int_distribution<unsigned long long>(p));

    return 0;
}
