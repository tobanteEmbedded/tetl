// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/bit.hpp>

#include <bit>

template <typename UInt>
[[nodiscard]] auto fuzz_popcount(FuzzedDataProvider& p) -> int
{
    auto const num = p.ConsumeIntegral<UInt>();
    auto const s   = std::popcount(num);
    auto const e   = etl::popcount(num);
    auto const f   = etl::detail::popcount_fallback(num);

    return (e != s or f != s) ? 1 : 0;
}

extern "C" auto LLVMFuzzerTestOneInput(etl::uint8_t const* data, etl::size_t size) -> int
{
    if (size == 0) {
        return 0;
    }

    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_popcount<unsigned char>(p));
    RUN(fuzz_popcount<unsigned short>(p));
    RUN(fuzz_popcount<unsigned int>(p));
    RUN(fuzz_popcount<unsigned long>(p));
    RUN(fuzz_popcount<unsigned long long>(p));
    return 0;
}
