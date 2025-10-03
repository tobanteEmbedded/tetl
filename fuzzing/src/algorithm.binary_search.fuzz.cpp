// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/algorithm.hpp>
#include <etl/span.hpp>

#include <algorithm>

[[nodiscard]] static auto fuzz_binary_search(FuzzedDataProvider& p) -> int
{
    auto const needle   = p.ConsumeIntegral<unsigned char>();
    auto const haystack = p.ConsumeRemainingBytes<unsigned char>();
    auto const view     = etl::span<unsigned char const>{haystack.data(), haystack.size()};

    auto const e = etl::binary_search(view.begin(), view.end(), needle);
    auto const s = std::binary_search(view.begin(), view.end(), needle);
    if (e != s) {
        return 1;
    }

    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_binary_search(p));
    return 0;
}
