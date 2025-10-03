// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/algorithm.hpp>
#include <etl/cstdint.hpp>
#include <etl/limits.hpp>
#include <etl/span.hpp>

#include <algorithm>
#include <print>

[[nodiscard]] auto fuzz_set_difference(FuzzedDataProvider& p) -> int
{
    auto const a     = p.ConsumeRandomLengthString(16);
    auto const b     = p.ConsumeRandomLengthString(16);
    auto const aview = etl::span<char const>{a.c_str(), a.size()};
    auto const bview = etl::span<char const>{b.c_str(), b.size()};

    auto eout = std::string{};
    auto sout = std::string{};

    etl::set_difference(aview.begin(), aview.end(), bview.begin(), bview.end(), std::back_inserter(eout));
    std::set_difference(aview.begin(), aview.end(), bview.begin(), bview.end(), std::back_inserter(sout));

    if (eout != sout) {
        std::println(stderr, "set_difference: '{}' and '{}'", a, b);
        std::println(stderr, "etl: '{}'", eout);
        std::println(stderr, "std: '{}'", sout);
        return 1;
    }

    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(etl::uint8_t const* data, etl::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_set_difference(p));
    return 0;
}
