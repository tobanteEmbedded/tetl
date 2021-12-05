/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#ifndef TETL_NUMERIC_MIDPOINT_HPP
#define TETL_NUMERIC_MIDPOINT_HPP

#include "etl/_concepts/requires.hpp"
#include "etl/_cstddef/ptrdiff_t.hpp"
#include "etl/_limits/numeric_limits.hpp"
#include "etl/_numeric/abs.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_floating_point.hpp"
#include "etl/_type_traits/is_integral.hpp"
#include "etl/_type_traits/is_pointer.hpp"
#include "etl/_type_traits/is_same.hpp"
#include "etl/_type_traits/make_unsigned.hpp"

namespace etl {

/// \brief Returns half the sum of a + b. If the sum is odd, the result is
/// rounded towards a.
///
/// \details CppCon 2019: Marshall Clow "midpoint? How Hard Could it Be?”
///
/// https://www.youtube.com/watch?v=sBtAGxBh-XI)
/// https://en.cppreference.com/w/cpp/numeric/midpoint
///
/// \group midpoint
template <typename Int,
    TETL_REQUIRES_((is_integral_v<Int> && !is_same_v<Int, bool>))>
constexpr auto midpoint(Int a, Int b) noexcept -> Int
{
    using U = make_unsigned_t<Int>;

    auto sign = 1;
    auto m    = static_cast<U>(a);
    auto n    = static_cast<U>(b);

    if (a > b) {
        sign = -1;
        m    = static_cast<U>(b);
        n    = static_cast<U>(a);
    }

    return static_cast<Int>(
        a + static_cast<Int>(sign * static_cast<Int>(U(n - m) >> 1)));
}

/// \group midpoint
template <typename Float, TETL_REQUIRES_(is_floating_point_v<Float>)>
constexpr auto midpoint(Float a, Float b) noexcept -> Float
{
    auto const lo = numeric_limits<Float>::min() * 2;
    auto const hi = numeric_limits<Float>::max() / 2;

    if (etl::abs(a) <= hi && etl::abs(b) <= hi) { return (a + b) / 2; }
    if (etl::abs(a) < lo) { return a + b / 2; }
    if (etl::abs(b) < lo) { return a / 2 + b; }

    return a / 2 + b / 2;
}

/// \group midpoint
/// \synopsis_return Ptr
template <typename Ptr, enable_if_t<is_pointer_v<Ptr>, int> = 0>
constexpr auto midpoint(Ptr a, Ptr b) noexcept -> Ptr
{
    return a + midpoint(ptrdiff_t { 0 }, b - a);
}

} // namespace etl

#endif // TETL_NUMERIC_MIDPOINT_HPP