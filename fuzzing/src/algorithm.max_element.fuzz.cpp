// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/algorithm.hpp>
#include <etl/iterator.hpp>
#include <etl/vector.hpp>

#include <algorithm>

template <typename IntType>
[[nodiscard]] auto fuzz_max_element(FuzzedDataProvider& p) -> int
{
    auto generator = [&p] { return p.ConsumeIntegral<IntType>(); };
    auto src       = etl::static_vector<IntType, 128>{};
    etl::generate_n(etl::back_inserter(src), src.capacity(), generator);

    auto e = etl::max_element(begin(src), end(src));
    auto s = std::max_element(begin(src), end(src));
    if (e != s) {
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
    RUN(fuzz_max_element<int>(p));

    return 0;
}
