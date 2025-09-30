// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/algorithm.hpp>
#include <etl/iterator.hpp>
#include <etl/vector.hpp>

#include <algorithm>

template <typename IntType>
[[nodiscard]] auto fuzz_equal(FuzzedDataProvider& p) -> int
{
    auto generator = [&p] { return p.ConsumeIntegral<IntType>(); };
    auto lhs       = etl::static_vector<IntType, 16>{};
    etl::generate_n(etl::back_inserter(lhs), lhs.capacity(), generator);

    auto rhs = etl::static_vector<IntType, 16>{};
    etl::generate_n(etl::back_inserter(rhs), rhs.capacity(), generator);

    auto e = etl::equal(begin(lhs), end(lhs), begin(rhs), end(rhs));
    auto s = std::equal(begin(lhs), end(lhs), begin(rhs), end(rhs));
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
    RUN(fuzz_equal<int>(p));
    return 0;
}
