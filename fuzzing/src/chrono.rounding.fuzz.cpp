// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/chrono.hpp>

#include <chrono>
#include <print>

[[nodiscard]] static auto fuzz_rounding(FuzzedDataProvider& p) -> int
{
    auto const milli = p.ConsumeIntegral<int>();

    auto const emilli = etl::chrono::sys_time<etl::chrono::milliseconds>{etl::chrono::milliseconds{milli}};
    auto const smilli = std::chrono::sys_time<std::chrono::milliseconds>{std::chrono::milliseconds{milli}};

    {
        auto const emin = etl::chrono::round<etl::chrono::minutes>(emilli);
        auto const smin = std::chrono::round<std::chrono::minutes>(smilli);

        if (emin.time_since_epoch().count() != smin.time_since_epoch().count()) {
            std::println(stderr, "round<minutes> mismatch from {}", smilli);
            std::println(stderr, "etl: {}", emin.time_since_epoch().count());
            std::println(stderr, "std: {}", smin.time_since_epoch().count());
            return 1;
        }
    }

    {
        auto const emin = etl::chrono::floor<etl::chrono::minutes>(emilli);
        auto const smin = std::chrono::floor<std::chrono::minutes>(smilli);

        if (emin.time_since_epoch().count() != smin.time_since_epoch().count()) {
            std::println(stderr, "floor<minutes> mismatch from {}", smilli);
            std::println(stderr, "etl: {}", emin.time_since_epoch().count());
            std::println(stderr, "std: {}", smin.time_since_epoch().count());
            return 1;
        }
    }

    {
        auto const emin = etl::chrono::ceil<etl::chrono::minutes>(emilli);
        auto const smin = std::chrono::ceil<std::chrono::minutes>(smilli);

        if (emin.time_since_epoch().count() != smin.time_since_epoch().count()) {
            std::println(stderr, "ceil<minutes> mismatch from {}", smilli);
            std::println(stderr, "etl: {}", emin.time_since_epoch().count());
            std::println(stderr, "std: {}", smin.time_since_epoch().count());
            return 1;
        }
    }

    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(etl::uint8_t const* data, etl::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_rounding(p));
    return 0;
}
