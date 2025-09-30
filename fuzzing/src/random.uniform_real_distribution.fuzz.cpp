// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/cstdint.hpp>
#include <etl/random.hpp>

#include <print>

template <typename Float>
[[nodiscard]] auto fuzz_uniform_real_distribution(FuzzedDataProvider& p) -> int
{
    static constexpr auto min = etl::numeric_limits<Float>::lowest();
    static constexpr auto max = etl::numeric_limits<Float>::max();

    auto const dist_min = p.ConsumeFloatingPointInRange<Float>(min, max);
    auto const dist_max = p.ConsumeFloatingPointInRange<Float>(min, max);
    if (dist_max <= dist_min) {
        return 0;
    }

    auto urng = etl::xoshiro128starstar{p.ConsumeIntegral<etl::uint32_t>()};
    auto dist = etl::uniform_real_distribution<Float>{dist_min, dist_max};
    if (auto const val = dist(urng); val < dist_min or val > dist_max) {
        std::println("dist_min: {}, dist_max: {}, val: {}", dist_min, dist_max, val);
        return 1;
    }
    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(etl::uint8_t const* data, etl::size_t size) -> int
{
    if (size == 0) {
        return 0;
    }

    auto p = FuzzedDataProvider{data, size};

    RUN(fuzz_uniform_real_distribution<float>(p));
    RUN(fuzz_uniform_real_distribution<double>(p));

    return 0;
}
