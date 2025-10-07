// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch
#pragma once

#include "fuzzing.hpp"

#include <etl/algorithm.hpp>
#include <etl/functional.hpp>
#include <etl/span.hpp>

#include <algorithm>
#include <print>

[[nodiscard]] inline auto test_sort(FuzzedDataProvider& p, auto sorter) -> int
{
    auto data = p.ConsumeRemainingBytes<unsigned char>();
    auto view = etl::span<unsigned char>{data.data(), data.size()};

    sorter(view.begin(), view.end(), etl::less());
    if (not std::is_sorted(view.begin(), view.end(), etl::less())) {
        std::println(stderr, "Data is not sorted via etl::less. Size = {}", view.size());
        return 1;
    }

    sorter(view.begin(), view.end(), etl::greater());
    if (not std::is_sorted(view.begin(), view.end(), etl::greater())) {
        std::println(stderr, "Data is not sorted via etl::greater. Size = {}", view.size());
        return 1;
    }

    return 0;
}

#define SORT_FUZZ_MAIN(sorter)                                                                                         \
    extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int                          \
    {                                                                                                                  \
        auto p = FuzzedDataProvider{data, size};                                                                       \
        RUN(test_sort(p, [](auto f, auto l, auto cmp) { sorter(f, l, cmp); }));                                        \
        return 0;                                                                                                      \
    }
