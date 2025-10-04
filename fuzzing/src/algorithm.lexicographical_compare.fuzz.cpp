// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/algorithm.hpp>
#include <etl/string_view.hpp>

#include <algorithm>

[[nodiscard]] static auto fuzz_lexicographical_compare(FuzzedDataProvider& p) -> int
{
    auto const a = p.ConsumeRandomLengthString();
    auto const b = p.ConsumeRandomLengthString();

    auto const va = etl::string_view{a.data(), a.size()};
    auto const vb = etl::string_view{b.data(), b.size()};

    auto const e = etl::lexicographical_compare(va.begin(), va.end(), vb.begin(), vb.end());
    auto const s = std::lexicographical_compare(va.begin(), va.end(), vb.begin(), vb.end());
    if (e != s) {
        return 1;
    }

    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_lexicographical_compare(p));
    return 0;
}
