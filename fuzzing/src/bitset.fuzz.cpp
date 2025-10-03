// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/bitset.hpp>
#include <etl/cstddef.hpp>

#include <bitset>
#include <print>

template <etl::size_t Size>
static auto fuzz_bitset(FuzzedDataProvider& p) -> int
{
    using UInt = etl::conditional_t<(Size > 32), etl::uint64_t, etl::uint32_t>;

    auto const val = p.ConsumeIntegral<UInt>();

    auto const eset = etl::bitset<Size>{val};
    auto const sset = std::bitset<Size>{val};

    auto const estr = eset.template to_string<Size>();
    auto const sstr = sset.to_string();

    auto const eview = etl::string_view{estr.data(), estr.size()};
    auto const sview = etl::string_view{sstr.data(), sstr.size()};

    auto const elong = eset.to_ullong();
    auto const slong = sset.to_ullong();

    if ((eview != sview) or (elong != slong)) {
        std::println("etl::bitset::to_ullong");
        std::println("val: '{}'", static_cast<unsigned long long>(val));
        std::println("estr: '{}'\nsstr: '{}'", estr.c_str(), sstr);
        std::println("elong: '{}' slong: '{}'", elong, slong);
        return 1;
    }

    auto const efromstr = etl::bitset<Size>{estr.c_str()};

    if (eset != efromstr) {
        std::println("etl::bitset(string_view)");
        std::println("estr: '{}'\nefromstr: '{}'", estr.c_str(), efromstr.template to_string<Size>().c_str());
        return 1;
    }

    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_bitset<24>(p));
    RUN(fuzz_bitset<32>(p));
    RUN(fuzz_bitset<64>(p));
    return 0;
}
