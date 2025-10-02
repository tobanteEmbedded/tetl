// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/bit.hpp>

#include <bit>

template <typename UInt>
[[nodiscard]] auto fuzz_countr_one(FuzzedDataProvider& p) -> int
{
    auto const num = p.ConsumeIntegral<UInt>();
    auto const s   = std::countr_one(num);
    auto const e   = etl::countr_one(num);
    return (e != s) ? 1 : 0;
}

extern "C" auto LLVMFuzzerTestOneInput(etl::uint8_t const* data, etl::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_countr_one<unsigned char>(p));
    RUN(fuzz_countr_one<unsigned short>(p));
    RUN(fuzz_countr_one<unsigned int>(p));
    RUN(fuzz_countr_one<unsigned long>(p));
    RUN(fuzz_countr_one<unsigned long long>(p));
    return 0;
}
