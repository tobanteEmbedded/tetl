// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/algorithm.hpp>
#include <etl/iterator.hpp>
#include <etl/vector.hpp>

template <typename IntType>
[[nodiscard]] auto fuzz_search(FuzzedDataProvider& p) -> int
{
    auto generator = [&p] { return p.ConsumeIntegral<IntType>(); };
    auto src       = etl::static_vector<IntType, 128>{};
    etl::generate_n(etl::back_inserter(src), src.capacity(), generator);

    auto objs = etl::static_vector<IntType, 4>{};
    etl::generate_n(etl::back_inserter(objs), objs.capacity(), generator);

    auto e = etl::search(src.begin(), src.end(), objs.begin(), objs.end());
    auto s = std::search(src.begin(), src.end(), objs.begin(), objs.end());
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
    RUN(fuzz_search<int>(p));

    return 0;
}
