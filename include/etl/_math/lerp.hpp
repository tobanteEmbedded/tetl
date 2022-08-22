/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_MATH_LERP_HPP
#define TETL_MATH_LERP_HPP

namespace etl::detail {

template <typename Float>
[[nodiscard]] constexpr auto lerp_impl(Float a, Float b, Float t) noexcept -> Float
{
    if ((a <= 0 && b >= 0) || (a >= 0 && b <= 0)) { return t * b + (1 - t) * a; }

    if (t == 1) { return b; }

    auto const x = a + t * (b - a);
    if ((t > 1) == (b > a)) { return b < x ? x : b; }
    return x < b ? x : b;
}

} // namespace etl::detail

#endif // TETL_MATH_LERP_HPP
