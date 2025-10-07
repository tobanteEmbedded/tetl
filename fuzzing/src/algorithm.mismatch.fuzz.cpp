// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/algorithm.hpp>
#include <etl/iterator.hpp>
#include <etl/vector.hpp>

template <typename IntType>
[[nodiscard]] static auto fuzz_mismatch(FuzzedDataProvider& p) -> int
{
    auto const a = p.ConsumeRandomLengthString();
    auto const b = p.ConsumeRandomLengthString();

    auto const e = etl::mismatch(a.begin(), a.end(), b.begin(), b.end());
    auto const s = std::mismatch(a.begin(), a.end(), b.begin(), b.end());
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
