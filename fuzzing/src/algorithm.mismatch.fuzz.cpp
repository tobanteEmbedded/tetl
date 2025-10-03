// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/algorithm.hpp>
#include <etl/iterator.hpp>
#include <etl/vector.hpp>

template <typename IntType>
[[nodiscard]] static auto fuzz_mismatch(FuzzedDataProvider& p) -> int
{
    auto generator = [&p] { return p.ConsumeIntegral<IntType>(); };
    auto src       = etl::static_vector<IntType, 128>{};
    etl::generate_n(etl::back_inserter(src), src.capacity(), generator);

    auto objs = etl::static_vector<IntType, 4>{};
    etl::generate_n(etl::back_inserter(objs), objs.capacity(), generator);

    auto e = etl::mismatch(src.begin(), src.end(), objs.begin(), objs.end());
    auto s = std::mismatch(src.begin(), src.end(), objs.begin(), objs.end());
    if ((e.first != s.first) or (e.second != s.second)) {
        return 1;
    }

    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_mismatch<int>(p));
    return 0;
}
