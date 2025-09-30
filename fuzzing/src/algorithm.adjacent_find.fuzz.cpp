// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/algorithm.hpp>
#include <etl/span.hpp>

#include <algorithm>

[[nodiscard]] static auto fuzz_adjacent_find(FuzzedDataProvider& p) -> int
{
    auto const bytes = p.ConsumeRemainingBytes<unsigned char>();
    auto const view  = etl::span<unsigned char const>{bytes.data(), bytes.size()};

    auto const e = etl::adjacent_find(view.begin(), view.end());
    auto const s = std::adjacent_find(view.begin(), view.end());
    if (e != s) {
        return 1;
    }

    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(etl::uint8_t const* data, etl::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_adjacent_find(p));
    return 0;
}
