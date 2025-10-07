// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/algorithm.hpp>
#include <etl/functional.hpp>
#include <etl/span.hpp>

template <typename IntType>
[[nodiscard]] static auto fuzz_search(FuzzedDataProvider& p) -> int
{
    auto const haystack = p.ConsumeRandomLengthString();
    auto const needle   = p.ConsumeRandomLengthString();

    auto const h = etl::span<char const>{haystack.data(), haystack.size()};
    auto const n = etl::span<char const>{needle.data(), needle.size()};

    auto const s = std::search(h.begin(), h.end(), n.begin(), n.end());
    auto const e = etl::search(h.begin(), h.end(), n.begin(), n.end());
    auto const d = etl::search(h.begin(), h.end(), etl::default_searcher(n.begin(), n.end()));
    if (e != s or d != s) {
        return 1;
    }

    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_search<int>(p));
    return 0;
}
