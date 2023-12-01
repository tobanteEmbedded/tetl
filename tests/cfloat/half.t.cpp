// SPDX-License-Identifier: BSL-1.0

#include "etl/cfloat.hpp"

#include "testing/testing.hpp"

constexpr auto test_inf() -> bool
{
    using etl::binary;
    using etl::half;

    assert(etl::isinf(half {binary, 0b0111'1100'0000'0000})); // +inf
    assert(etl::isinf(half {binary, 0b1111'1100'0000'0000})); // -inf

    assert(!etl::isinf(half {binary, 0b0000'0000'0000'0000})); // +0
    assert(!etl::isinf(half {binary, 0b1000'0000'0000'0000})); // -0
    assert(!etl::isinf(half {binary, 0b0000'0000'0000'0001})); // subnormal
    assert(!etl::isinf(half {binary, 0b0000'0000'0000'0011})); // subnormal

    assert(!etl::isinf(half {binary, 0b0111'1100'0000'0001})); // +nan
    assert(!etl::isinf(half {binary, 0b1111'1100'0000'0001})); // -nan

    return true;
}

constexpr auto test_nan() -> bool
{
    using etl::binary;
    using etl::half;

    assert(etl::isnan(half {binary, 0b0111'1100'0000'0001})); // +nan
    assert(etl::isnan(half {binary, 0b1111'1100'0000'0001})); // -nan

    assert(!etl::isnan(half {binary, 0b0000'0000'0000'0000})); // +0
    assert(!etl::isnan(half {binary, 0b1000'0000'0000'0000})); // -0
    assert(!etl::isnan(half {binary, 0b0000'0000'0000'0001})); // subnormal
    assert(!etl::isnan(half {binary, 0b0000'0000'0000'0011})); // subnormal

    assert(!etl::isnan(half {binary, 0b0111'1100'0000'0000})); // +inf
    assert(!etl::isnan(half {binary, 0b1111'1100'0000'0000})); // -inf

    return true;
}

constexpr auto test_normal() -> bool
{
    using etl::binary;
    using etl::half;

    assert(etl::isnormal(half {binary, 0b0011'1100'0000'0000})); // +1
    assert(etl::isnormal(half {binary, 0b1011'1100'0000'0000})); // -1
    assert(etl::isnormal(half {binary, 0b0011'1110'0000'0000})); // +1.5
    assert(etl::isnormal(half {binary, 0b1011'1110'0000'0000})); // -1.5

    assert(!etl::isnormal(half {binary, 0b0000'0000'0000'0000})); // +0
    assert(!etl::isnormal(half {binary, 0b1000'0000'0000'0000})); // -0
    assert(!etl::isnormal(half {binary, 0b0000'0000'0000'0001})); // +sub
    assert(!etl::isnormal(half {binary, 0b1000'0000'0000'0001})); // -sub

    assert(!etl::isnormal(half {binary, 0b0111'1100'0000'0000})); // +inf
    assert(!etl::isnormal(half {binary, 0b1111'1100'0000'0000})); // -inf

    assert(!etl::isnormal(half {binary, 0b0111'1100'0000'0001})); // +nan
    assert(!etl::isnormal(half {binary, 0b1111'1100'0000'0001})); // -nan

    return true;
}
constexpr auto test_finite() -> bool
{
    using etl::binary;
    using etl::half;

    assert(etl::isfinite(half {binary, 0b0000'0000'0000'0000})); // +0
    assert(etl::isfinite(half {binary, 0b1000'0000'0000'0000})); // -0
    assert(etl::isfinite(half {binary, 0b0011'1100'0000'0000})); // +1
    assert(etl::isfinite(half {binary, 0b1011'1100'0000'0000})); // -1
    assert(etl::isfinite(half {binary, 0b0011'1110'0000'0000})); // +1.5
    assert(etl::isfinite(half {binary, 0b1011'1110'0000'0000})); // -1.5
    assert(etl::isfinite(half {binary, 0b0000'0000'0000'0001})); // -subnormal
    assert(etl::isfinite(half {binary, 0b1000'0000'0000'0001})); // +subnormal

    assert(!etl::isfinite(half {binary, 0b0111'1100'0000'0000})); // +inf
    assert(!etl::isfinite(half {binary, 0b1111'1100'0000'0000})); // -inf

    assert(!etl::isfinite(half {binary, 0b0111'1100'0000'0001})); // +nan
    assert(!etl::isfinite(half {binary, 0b1111'1100'0000'0001})); // -nan

    return true;
}

constexpr auto test_signbit() -> bool
{
    using etl::binary;
    using etl::half;

    assert(etl::signbit(half {binary, 0b1000'0000'0000'0000})); // -0
    assert(etl::signbit(half {binary, 0b1011'1100'0000'0000})); // -1
    assert(etl::signbit(half {binary, 0b1011'1110'0000'0000})); // -1.5
    assert(etl::signbit(half {binary, 0b1000'0000'0000'0001})); // -subnormal
    assert(etl::signbit(half {binary, 0b1111'1100'0000'0001})); // -nan
    assert(etl::signbit(half {binary, 0b1111'1100'0000'0000})); // -inf

    assert(!etl::signbit(half {binary, 0b0000'0000'0000'0000})); // +0
    assert(!etl::signbit(half {binary, 0b0011'1100'0000'0000})); // +1
    assert(!etl::signbit(half {binary, 0b0011'1110'0000'0000})); // +1.5
    assert(!etl::signbit(half {binary, 0b0000'0000'0000'0001})); // subnormal
    assert(!etl::signbit(half {binary, 0b0111'1100'0000'0000})); // +inf
    assert(!etl::signbit(half {binary, 0b0111'1100'0000'0001})); // +nan

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test_inf());
    assert(test_nan());
    assert(test_normal());
    assert(test_finite());
    assert(test_signbit());
    return true;
}

auto main() -> int
{
    assert(test_all());

#if __has_builtin(__builtin_bit_cast)
    static_assert(test_all());
#endif
    return 0;
}
