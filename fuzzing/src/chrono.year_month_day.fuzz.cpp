// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/chrono.hpp>

#include <chrono>
#include <print>

[[nodiscard]] static auto fuzz_year_month_day(FuzzedDataProvider& p) -> int
{
    auto const y = p.ConsumeIntegral<int>();
    auto const m = p.ConsumeIntegralInRange<unsigned>(0U, 255U);
    auto const d = p.ConsumeIntegralInRange<unsigned>(0U, 255U);

    auto const eymd = etl::chrono::year{y} / etl::chrono::month{m} / etl::chrono::day{d};
    auto const symd = std::chrono::year{y} / std::chrono::month{m} / std::chrono::day{d};

    if (eymd.ok() != symd.ok()) {
        std::println(stderr, "etl::chrono::year_month_day::ok() = {}", eymd.ok());
        std::println(stderr, "std::chrono::year_month_day::ok() = {}", symd.ok());
        return 1;
    }

    if (not eymd.ok()) {
        return 0;
    }

    auto const esys = static_cast<etl::chrono::sys_days>(eymd);
    auto const ssys = static_cast<std::chrono::sys_days>(symd);

    auto const ecount = esys.time_since_epoch().count();
    auto const scount = ssys.time_since_epoch().count();

    if (ecount != scount) {
        std::println(stderr, "etl::chrono::year_month_day::operator sys_days() = {}", ecount);
        std::println(stderr, "std::chrono::year_month_day::operator sys_days() = {}", scount);
        return 1;
    }

    // round-trip
    if (eymd != etl::chrono::year_month_day{esys}) {
        std::println(stderr, "std::chrono::year_month_day(sys_days) = {}", ecount);
        return 1;
    }

    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_year_month_day(p));
    return 0;
}
