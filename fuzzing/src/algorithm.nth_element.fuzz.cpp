// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/algorithm.hpp>
#include <etl/functional.hpp>
#include <etl/span.hpp>

#include <algorithm>
#include <print>

[[nodiscard]] auto fuzz_nth_element(FuzzedDataProvider& p) -> int
{
    auto str = p.ConsumeRandomLengthString(16);
    std::transform(str.begin(), str.end(), str.begin(), [](char c) {
        c = std::isspace(c) ? '0' : c;
        c = !std::isgraph(c) ? '0' : c;
        return c;
    });

    auto const original = str;
    auto const pos      = p.ConsumeIntegralInRange<unsigned>(0, str.empty() ? 0 : str.size() - 1);

    auto const view = etl::span<char>{str.data(), str.size()};
    auto const nth  = etl::next(view.begin(), static_cast<etl::ptrdiff_t>(pos));

    etl::nth_element(view.begin(), nth, view.end());
    if (view.empty()) {
        return 0;
    }

    for (auto i{view.begin()}; i < nth; ++i) {
        for (auto j{nth}; j < view.end(); ++j) {
            if (*j < *i) {
                std::println(
                    stderr,
                    "nth_element: Not partitioned '{}' pos {}, size {} ",
                    original,
                    pos,
                    original.size()
                );
                return 1;
            }
        }
    }

    auto const nthValue = *nth;
    std::sort(view.begin(), view.end());
    if (nthValue != *nth) {
        std::println(
            stderr,
            "nth_element: nth value incorrect for '{}' at {} Is: '{}', should: '{}'",
            original,
            pos,
            nthValue,
            *nth
        );
        return 1;
    }

    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(etl::uint8_t const* data, etl::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_nth_element(p));
    return 0;
}
