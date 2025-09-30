// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/algorithm.hpp>
#include <etl/span.hpp>

#include <algorithm>

[[nodiscard]] static auto fuzz_lexicographical_compare(FuzzedDataProvider& p) -> int
{
    auto const a = p.ConsumeBytes<unsigned char>(64);
    auto const b = p.ConsumeBytes<unsigned char>(64);

    auto const va = etl::span<unsigned char const>{a.data(), a.size()};
    auto const vb = etl::span<unsigned char const>{b.data(), b.size()};

    auto const e = etl::lexicographical_compare(va.begin(), va.end(), vb.begin(), vb.end());
    auto const s = std::lexicographical_compare(va.begin(), va.end(), vb.begin(), vb.end());
    if (e != s) {
        return 1;
    }

    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(etl::uint8_t const* data, etl::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_lexicographical_compare(p));
    return 0;
}
