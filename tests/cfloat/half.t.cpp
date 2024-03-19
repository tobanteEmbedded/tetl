// SPDX-License-Identifier: BSL-1.0

#include <etl/cfloat.hpp>

#include "testing/testing.hpp"

constexpr auto test_inf() -> bool
{
    using etl::binary;
    using etl::half;

    CHECK(etl::isinf(half{binary, 0b0111'1100'0000'0000})); // +inf
    CHECK(etl::isinf(half{binary, 0b1111'1100'0000'0000})); // -inf

    CHECK(!etl::isinf(half{binary, 0b0000'0000'0000'0000})); // +0
    CHECK(!etl::isinf(half{binary, 0b1000'0000'0000'0000})); // -0
    CHECK(!etl::isinf(half{binary, 0b0000'0000'0000'0001})); // subnormal
    CHECK(!etl::isinf(half{binary, 0b0000'0000'0000'0011})); // subnormal

    CHECK(!etl::isinf(half{binary, 0b0111'1100'0000'0001})); // +nan
    CHECK(!etl::isinf(half{binary, 0b1111'1100'0000'0001})); // -nan

    return true;
}

constexpr auto test_nan() -> bool
{
    using etl::binary;
    using etl::half;

    CHECK(etl::isnan(half{binary, 0b0111'1100'0000'0001})); // +nan
    CHECK(etl::isnan(half{binary, 0b1111'1100'0000'0001})); // -nan

    CHECK(!etl::isnan(half{binary, 0b0000'0000'0000'0000})); // +0
    CHECK(!etl::isnan(half{binary, 0b1000'0000'0000'0000})); // -0
    CHECK(!etl::isnan(half{binary, 0b0000'0000'0000'0001})); // subnormal
    CHECK(!etl::isnan(half{binary, 0b0000'0000'0000'0011})); // subnormal

    CHECK(!etl::isnan(half{binary, 0b0111'1100'0000'0000})); // +inf
    CHECK(!etl::isnan(half{binary, 0b1111'1100'0000'0000})); // -inf

    return true;
}

constexpr auto test_normal() -> bool
{
    using etl::binary;
    using etl::half;

    CHECK(etl::isnormal(half{binary, 0b0011'1100'0000'0000})); // +1
    CHECK(etl::isnormal(half{binary, 0b1011'1100'0000'0000})); // -1
    CHECK(etl::isnormal(half{binary, 0b0011'1110'0000'0000})); // +1.5
    CHECK(etl::isnormal(half{binary, 0b1011'1110'0000'0000})); // -1.5

    CHECK(!etl::isnormal(half{binary, 0b0000'0000'0000'0000})); // +0
    CHECK(!etl::isnormal(half{binary, 0b1000'0000'0000'0000})); // -0
    CHECK(!etl::isnormal(half{binary, 0b0000'0000'0000'0001})); // +sub
    CHECK(!etl::isnormal(half{binary, 0b1000'0000'0000'0001})); // -sub

    CHECK(!etl::isnormal(half{binary, 0b0111'1100'0000'0000})); // +inf
    CHECK(!etl::isnormal(half{binary, 0b1111'1100'0000'0000})); // -inf

    CHECK(!etl::isnormal(half{binary, 0b0111'1100'0000'0001})); // +nan
    CHECK(!etl::isnormal(half{binary, 0b1111'1100'0000'0001})); // -nan

    return true;
}

constexpr auto test_finite() -> bool
{
    using etl::binary;
    using etl::half;

    CHECK(etl::isfinite(half{binary, 0b0000'0000'0000'0000})); // +0
    CHECK(etl::isfinite(half{binary, 0b1000'0000'0000'0000})); // -0
    CHECK(etl::isfinite(half{binary, 0b0011'1100'0000'0000})); // +1
    CHECK(etl::isfinite(half{binary, 0b1011'1100'0000'0000})); // -1
    CHECK(etl::isfinite(half{binary, 0b0011'1110'0000'0000})); // +1.5
    CHECK(etl::isfinite(half{binary, 0b1011'1110'0000'0000})); // -1.5
    CHECK(etl::isfinite(half{binary, 0b0000'0000'0000'0001})); // -subnormal
    CHECK(etl::isfinite(half{binary, 0b1000'0000'0000'0001})); // +subnormal

    CHECK(!etl::isfinite(half{binary, 0b0111'1100'0000'0000})); // +inf
    CHECK(!etl::isfinite(half{binary, 0b1111'1100'0000'0000})); // -inf

    CHECK(!etl::isfinite(half{binary, 0b0111'1100'0000'0001})); // +nan
    CHECK(!etl::isfinite(half{binary, 0b1111'1100'0000'0001})); // -nan

    return true;
}

constexpr auto test_signbit() -> bool
{
    using etl::binary;
    using etl::half;

    CHECK(etl::signbit(half{binary, 0b1000'0000'0000'0000})); // -0
    CHECK(etl::signbit(half{binary, 0b1011'1100'0000'0000})); // -1
    CHECK(etl::signbit(half{binary, 0b1011'1110'0000'0000})); // -1.5
    CHECK(etl::signbit(half{binary, 0b1000'0000'0000'0001})); // -subnormal
    CHECK(etl::signbit(half{binary, 0b1111'1100'0000'0001})); // -nan
    CHECK(etl::signbit(half{binary, 0b1111'1100'0000'0000})); // -inf

    CHECK(!etl::signbit(half{binary, 0b0000'0000'0000'0000})); // +0
    CHECK(!etl::signbit(half{binary, 0b0011'1100'0000'0000})); // +1
    CHECK(!etl::signbit(half{binary, 0b0011'1110'0000'0000})); // +1.5
    CHECK(!etl::signbit(half{binary, 0b0000'0000'0000'0001})); // subnormal
    CHECK(!etl::signbit(half{binary, 0b0111'1100'0000'0000})); // +inf
    CHECK(!etl::signbit(half{binary, 0b0111'1100'0000'0001})); // +nan

    return true;
}

constexpr auto test_all() -> bool
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
