// SPDX-License-Identifier: BSL-1.0

#include <etl/cfloat.hpp>

#include "testing/testing.hpp"

static constexpr auto test_inf() -> bool
{
    CHECK(etl::isinf(etl::half{etl::binary, 0b0111'1100'0000'0000})); // +inf
    CHECK(etl::isinf(etl::half{etl::binary, 0b1111'1100'0000'0000})); // -inf

    CHECK_FALSE(etl::isinf(etl::half{etl::binary, 0b0000'0000'0000'0000})); // +0
    CHECK_FALSE(etl::isinf(etl::half{etl::binary, 0b1000'0000'0000'0000})); // -0
    CHECK_FALSE(etl::isinf(etl::half{etl::binary, 0b0000'0000'0000'0001})); // subnormal
    CHECK_FALSE(etl::isinf(etl::half{etl::binary, 0b0000'0000'0000'0011})); // subnormal

    CHECK_FALSE(etl::isinf(etl::half{etl::binary, 0b0111'1100'0000'0001})); // +nan
    CHECK_FALSE(etl::isinf(etl::half{etl::binary, 0b1111'1100'0000'0001})); // -nan

    return true;
}

static constexpr auto test_nan() -> bool
{
    CHECK(etl::isnan(etl::half{etl::binary, 0b0111'1100'0000'0001})); // +nan
    CHECK(etl::isnan(etl::half{etl::binary, 0b1111'1100'0000'0001})); // -nan

    CHECK_FALSE(etl::isnan(etl::half{etl::binary, 0b0000'0000'0000'0000})); // +0
    CHECK_FALSE(etl::isnan(etl::half{etl::binary, 0b1000'0000'0000'0000})); // -0
    CHECK_FALSE(etl::isnan(etl::half{etl::binary, 0b0000'0000'0000'0001})); // subnormal
    CHECK_FALSE(etl::isnan(etl::half{etl::binary, 0b0000'0000'0000'0011})); // subnormal

    CHECK_FALSE(etl::isnan(etl::half{etl::binary, 0b0111'1100'0000'0000})); // +inf
    CHECK_FALSE(etl::isnan(etl::half{etl::binary, 0b1111'1100'0000'0000})); // -inf

    return true;
}

static constexpr auto test_normal() -> bool
{
    CHECK(etl::isnormal(etl::half{etl::binary, 0b0011'1100'0000'0000})); // +1
    CHECK(etl::isnormal(etl::half{etl::binary, 0b1011'1100'0000'0000})); // -1
    CHECK(etl::isnormal(etl::half{etl::binary, 0b0011'1110'0000'0000})); // +1.5
    CHECK(etl::isnormal(etl::half{etl::binary, 0b1011'1110'0000'0000})); // -1.5

    CHECK_FALSE(etl::isnormal(etl::half{etl::binary, 0b0000'0000'0000'0000})); // +0
    CHECK_FALSE(etl::isnormal(etl::half{etl::binary, 0b1000'0000'0000'0000})); // -0
    CHECK_FALSE(etl::isnormal(etl::half{etl::binary, 0b0000'0000'0000'0001})); // +sub
    CHECK_FALSE(etl::isnormal(etl::half{etl::binary, 0b1000'0000'0000'0001})); // -sub

    CHECK_FALSE(etl::isnormal(etl::half{etl::binary, 0b0111'1100'0000'0000})); // +inf
    CHECK_FALSE(etl::isnormal(etl::half{etl::binary, 0b1111'1100'0000'0000})); // -inf

    CHECK_FALSE(etl::isnormal(etl::half{etl::binary, 0b0111'1100'0000'0001})); // +nan
    CHECK_FALSE(etl::isnormal(etl::half{etl::binary, 0b1111'1100'0000'0001})); // -nan

    return true;
}

static constexpr auto test_finite() -> bool
{
    CHECK(etl::isfinite(etl::half{etl::binary, 0b0000'0000'0000'0000})); // +0
    CHECK(etl::isfinite(etl::half{etl::binary, 0b1000'0000'0000'0000})); // -0
    CHECK(etl::isfinite(etl::half{etl::binary, 0b0011'1100'0000'0000})); // +1
    CHECK(etl::isfinite(etl::half{etl::binary, 0b1011'1100'0000'0000})); // -1
    CHECK(etl::isfinite(etl::half{etl::binary, 0b0011'1110'0000'0000})); // +1.5
    CHECK(etl::isfinite(etl::half{etl::binary, 0b1011'1110'0000'0000})); // -1.5
    CHECK(etl::isfinite(etl::half{etl::binary, 0b0000'0000'0000'0001})); // -subnormal
    CHECK(etl::isfinite(etl::half{etl::binary, 0b1000'0000'0000'0001})); // +subnormal

    CHECK_FALSE(etl::isfinite(etl::half{etl::binary, 0b0111'1100'0000'0000})); // +inf
    CHECK_FALSE(etl::isfinite(etl::half{etl::binary, 0b1111'1100'0000'0000})); // -inf

    CHECK_FALSE(etl::isfinite(etl::half{etl::binary, 0b0111'1100'0000'0001})); // +nan
    CHECK_FALSE(etl::isfinite(etl::half{etl::binary, 0b1111'1100'0000'0001})); // -nan

    return true;
}

static constexpr auto test_signbit() -> bool
{
    CHECK(etl::signbit(etl::half{etl::binary, 0b1000'0000'0000'0000})); // -0
    CHECK(etl::signbit(etl::half{etl::binary, 0b1011'1100'0000'0000})); // -1
    CHECK(etl::signbit(etl::half{etl::binary, 0b1011'1110'0000'0000})); // -1.5
    CHECK(etl::signbit(etl::half{etl::binary, 0b1000'0000'0000'0001})); // -subnormal
    CHECK(etl::signbit(etl::half{etl::binary, 0b1111'1100'0000'0001})); // -nan
    CHECK(etl::signbit(etl::half{etl::binary, 0b1111'1100'0000'0000})); // -inf

    CHECK_FALSE(etl::signbit(etl::half{etl::binary, 0b0000'0000'0000'0000})); // +0
    CHECK_FALSE(etl::signbit(etl::half{etl::binary, 0b0011'1100'0000'0000})); // +1
    CHECK_FALSE(etl::signbit(etl::half{etl::binary, 0b0011'1110'0000'0000})); // +1.5
    CHECK_FALSE(etl::signbit(etl::half{etl::binary, 0b0000'0000'0000'0001})); // subnormal
    CHECK_FALSE(etl::signbit(etl::half{etl::binary, 0b0111'1100'0000'0000})); // +inf
    CHECK_FALSE(etl::signbit(etl::half{etl::binary, 0b0111'1100'0000'0001})); // +nan

    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test_inf());
    CHECK(test_nan());
    CHECK(test_normal());
    CHECK(test_finite());
    CHECK(test_signbit());
    return true;
}

auto main() -> int
{
    CHECK(test_all());

#if __has_builtin(__builtin_bit_cast)
    static_assert(test_all());
#endif
    return 0;
}
