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
    auto const original = p.ConsumeRandomLengthString(8);
    auto const pos      = p.ConsumeIntegralInRange<unsigned>(0, original.empty() ? 0 : original.size() - 1);

    if (std::ranges::any_of(original, [](char c) { return std::isspace(c) != 0; })) {
        return 0;
    }
    // std::transform(original.begin(), original.end(), original.begin(), [](char c) { return std::isspace(c) ? '' : c;
    // });

    auto estr       = original;
    auto const view = etl::span<char>{estr.data(), estr.size()};
    etl::nth_element(view.begin(), view.begin() + static_cast<etl::ptrdiff_t>(pos), view.end());
    if (view.empty()) {
        return 0;
    }

    auto sstr = original;
    std::nth_element(sstr.begin(), sstr.begin() + static_cast<etl::ptrdiff_t>(pos), sstr.end());

    if (estr[pos] != sstr[pos]) {
        std::println(stderr, "nth_element mismatch at pos {}, etl: {}, std: {}", pos, estr[pos], sstr[pos]);
        std::println(stderr, "str: '{}'", original);
        std::println(stderr, "etl: '{}'", estr);
        std::println(stderr, "std: '{}'", sstr);
        return 1;
    }

    // for (auto i{view.begin()}; i < nth; ++i) {
    //     for (auto j{nth}; j < view.end(); ++j) {
    //         if (*j < *i) {
    //             std::println(stderr, "nth_element: Not partitioned '{}' pos {}, size {} ", str, pos,
    //             original.size()); return 1;
    //         }
    //     }
    // }

    // auto const nthValue = *nth;
    // std::sort(view.begin(), view.end());
    // if (nthValue != *nth) {
    //     std::println(
    //         stderr,
    //         "nth_element: nth value incorrect at {} Is: '{}', should: '{}'\n'{}'\n'{}'",
    //         pos,
    //         nthValue,
    //         *nth,
    //         original,
    //         str
    //     );
    //     return 1;
    // }

    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(etl::uint8_t const* data, etl::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_nth_element(p));
    return 0;
}
