// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "fuzzing.hpp"

#include <etl/cmath.hpp>

#include <cmath>

template <typename Float>
[[nodiscard]] auto fuzz_lerp(FuzzedDataProvider& p) -> int
{
    auto const a = p.ConsumeFloatingPoint<Float>();
    auto const b = p.ConsumeFloatingPoint<Float>();
    auto const t = p.ConsumeFloatingPoint<Float>();

    auto const s = std::lerp(a, b, t);
    auto const e = etl::lerp(a, b, t);

    if (std::isfinite(s) != std::isfinite(e)) {
        return 1;
    }

    if (std::isnan(s) or std::isinf(s)) {
        return 0;
    }

    if (s != e) {
        return 1;
    }

    return 0;
}

extern "C" auto LLVMFuzzerTestOneInput(etl::uint8_t const* data, etl::size_t size) -> int
{
    if (size == 0) {
        return 0;
    }

    auto p = FuzzedDataProvider{data, size};
    RUN(fuzz_lerp<float>(p));
    RUN(fuzz_lerp<double>(p));
    return 0;
}
