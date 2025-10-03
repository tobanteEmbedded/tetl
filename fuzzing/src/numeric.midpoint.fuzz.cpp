// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/concepts.hpp>
#include <etl/numeric.hpp>

#include <numeric>
#include <utility>

template <typename Number>
[[nodiscard]] static auto fuzz_midpoint(FuzzedDataProvider& p) -> int
{
    auto const [a, b] = [&p] {
        if constexpr (etl::integral<Number>) {
            return std::pair{p.ConsumeIntegral<Number>(), p.ConsumeIntegral<Number>()};
        } else if constexpr (etl::floating_point<Number>) {
            return std::pair{p.ConsumeFloatingPoint<Number>(), p.ConsumeFloatingPoint<Number>()};
        } else {
            static_assert(false);
        }
    }();

    auto const s = std::midpoint(a, b);
    auto const e = etl::midpoint(a, b);
    return s != e ? 1 : 0;
}

extern "C" auto LLVMFuzzerTestOneInput(etl::uint8_t const* data, etl::size_t size) -> int
{
    auto p = FuzzedDataProvider{data, size};

    RUN(fuzz_midpoint<unsigned char>(p));
    RUN(fuzz_midpoint<unsigned short>(p));
    RUN(fuzz_midpoint<unsigned int>(p));
    RUN(fuzz_midpoint<unsigned long>(p));
    RUN(fuzz_midpoint<unsigned long long>(p));

    RUN(fuzz_midpoint<signed char>(p));
    RUN(fuzz_midpoint<signed short>(p));
    RUN(fuzz_midpoint<signed int>(p));
    RUN(fuzz_midpoint<signed long>(p));
    RUN(fuzz_midpoint<signed long long>(p));

    RUN(fuzz_midpoint<float>(p));
    RUN(fuzz_midpoint<double>(p));
    return 0;
}
