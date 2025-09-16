// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/bitset.hpp>

#include <bitset>
#include <cstdio>

auto fuzz_bitset(FuzzedDataProvider& p) -> int
{
    auto const val = p.ConsumeIntegral<etl::uint32_t>();

    auto const eset = etl::bitset<32>{val};
    auto const sset = std::bitset<32>{val};

    auto const estr = eset.to_string<32>();
    auto const sstr = sset.to_string();

    auto const eview = etl::string_view{estr.data(), estr.size()};
    auto const sview = etl::string_view{sstr.data(), sstr.size()};

    auto const elong = eset.to_ullong();
    auto const slong = sset.to_ullong();

    if ((eview != sview) or (elong != slong)) {
        std::printf("etl::bitset::to_ullong\n");
        std::printf("val: '%u'\n", val);
        std::printf("estr: '%s'\nsstr: '%s'\n", estr.c_str(), sstr.c_str());
        std::printf("elong: '%llu' slong: '%llu'\n", elong, slong);
        return 1;
    }

    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    if (size == 0) {
        return 0;
    }
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_bitset(p));
    return 0;
}
