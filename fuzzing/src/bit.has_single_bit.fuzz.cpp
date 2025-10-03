// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/bit.hpp>

#include <bit>

template <typename UInt>
[[nodiscard]] static auto fuzz_has_single_bit(FuzzedDataProvider& p) -> int
{
    auto const num = p.ConsumeIntegral<UInt>();
    auto const s   = std::has_single_bit(num);
    auto const e   = etl::has_single_bit(num);

    return (e != s) ? 1 : 0;
}

extern "C" auto LLVMFuzzerTestOneInput(etl::uint8_t const* data, etl::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_has_single_bit<unsigned char>(p));
    RUN(fuzz_has_single_bit<unsigned short>(p));
    RUN(fuzz_has_single_bit<unsigned int>(p));
    RUN(fuzz_has_single_bit<unsigned long>(p));
    RUN(fuzz_has_single_bit<unsigned long long>(p));
    return 0;
}
