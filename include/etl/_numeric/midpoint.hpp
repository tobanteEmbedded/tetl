// SPDX-License-Identifier: BSL-1.0
#ifndef TETL_NUMERIC_MIDPOINT_HPP
#define TETL_NUMERIC_MIDPOINT_HPP

#include <etl/_concepts/floating_point.hpp>
#include <etl/_cstddef/ptrdiff_t.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_numeric/abs.hpp>
#include <etl/_type_traits/is_integral.hpp>
#include <etl/_type_traits/is_pointer.hpp>
#include <etl/_type_traits/is_same.hpp>
#include <etl/_type_traits/make_unsigned.hpp>

namespace etl {

/// \brief Returns half the sum of a + b. If the sum is odd, the result is
/// rounded towards a.
///
/// \details CppCon 2019: Marshall Clow "midpoint? How Hard Could it Be?"
///          Integer version was updated to match implementation from libc++.
///
/// https://www.youtube.com/watch?v=sBtAGxBh-XI)
/// https://en.cppreference.com/w/cpp/numeric/midpoint
template <typename Int>
    requires(etl::is_integral_v<Int> and not etl::is_same_v<Int, bool>)
constexpr auto midpoint(Int a, Int b) noexcept -> Int
{
    using UInt = etl::make_unsigned_t<Int>;

    auto const shift = static_cast<UInt>(etl::numeric_limits<UInt>::digits - 1);
    auto const diff  = static_cast<UInt>(UInt(b) - UInt(a));
    auto const sign  = static_cast<UInt>(b < a);
    auto const half  = static_cast<UInt>((diff / 2) + (sign << shift) + (sign & diff));

    return a + static_cast<Int>(half);
}

template <etl::floating_point Float>
constexpr auto midpoint(Float a, Float b) noexcept -> Float
{
    auto const lo = etl::numeric_limits<Float>::min() * 2;
    auto const hi = etl::numeric_limits<Float>::max() / 2;

    if (etl::abs(a) <= hi and etl::abs(b) <= hi) {
        return (a + b) / 2;
    }
    if (etl::abs(a) < lo) {
        return a + b / 2;
    }
    if (etl::abs(b) < lo) {
        return a / 2 + b;
    }

    return a / 2 + b / 2;
}

/// \synopsis_return Ptr
template <typename Ptr>
    requires etl::is_pointer_v<Ptr>
constexpr auto midpoint(Ptr a, Ptr b) noexcept -> Ptr
{
    return a + etl::midpoint(etl::ptrdiff_t(0), b - a);
}

} // namespace etl

#endif // TETL_NUMERIC_MIDPOINT_HPP
