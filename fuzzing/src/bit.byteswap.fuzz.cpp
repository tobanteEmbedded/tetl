// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/bit.hpp>
#include <etl/cstdint.hpp>

#include <bit>

template <typename UInt>
[[nodiscard]] auto fuzz_byteswap(FuzzedDataProvider& p) -> int
{
    auto const num = p.ConsumeIntegral<UInt>();
    auto const s   = std::byteswap(num);
    auto const e   = etl::byteswap(num);
    auto const f   = etl::detail::byteswap_fallback(num);
    return (e != s or f != s) ? 1 : 0;
}

extern "C" auto LLVMFuzzerTestOneInput(etl::uint8_t const* data, etl::size_t size) -> int
{
    if (size == 0) {
        return 0;
    }

    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_byteswap<etl::uint16_t>(p));
    RUN(fuzz_byteswap<etl::uint32_t>(p));
    RUN(fuzz_byteswap<etl::uint64_t>(p));
    return 0;
}
