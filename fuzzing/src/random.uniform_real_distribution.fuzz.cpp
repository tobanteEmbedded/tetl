// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/cstdint.hpp>
#include <etl/random.hpp>

#include <print>

template <typename Float>
[[nodiscard]] static auto fuzz_uniform_real_distribution(FuzzedDataProvider& p) -> int
{
    static constexpr auto min = etl::numeric_limits<Float>::lowest();
    static constexpr auto max = etl::numeric_limits<Float>::max();

    auto const distMin = p.ConsumeFloatingPointInRange<Float>(min, max);
    auto const distMax = p.ConsumeFloatingPointInRange<Float>(min, max);
    if (distMax <= distMin) {
        return 0;
    }

    auto urng = etl::xoshiro128starstar{p.ConsumeIntegral<etl::uint32_t>()};
    auto dist = etl::uniform_real_distribution<Float>{distMin, distMax};
    if (auto const val = dist(urng); val < distMin or val > distMax) {
        std::println("dist_min: {}, dist_max: {}, val: {}", distMin, distMax, val);
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

    RUN(fuzz_uniform_real_distribution<float>(p));
    RUN(fuzz_uniform_real_distribution<double>(p));

    return 0;
}
