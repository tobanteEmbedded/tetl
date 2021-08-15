// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_MATH_ABS_HPP
#define TETL_MATH_ABS_HPP

namespace etl {
namespace detail {

template <typename T>
[[nodiscard]] constexpr auto abs_impl(T n) noexcept -> T
{
    // constexpr auto isInt      = is_same_v<T, int>;
    // constexpr auto isLong     = is_same_v<T, long>;
    // constexpr auto isLongLong = is_same_v<T, long long>;
    // static_assert(isInt || isLong || isLongLong);

    if (n >= T(0)) { return n; }
    return n * T(-1);
}

} // namespace detail

/// \brief Computes the absolute value of an integer number. The behavior is
/// undefined if the result cannot be represented by the return type. If abs
/// is called with an unsigned integral argument that cannot be converted to int
/// by integral promotion, the program is ill-formed.
/// \group abs
/// \module Numeric
[[nodiscard]] constexpr auto abs(int n) noexcept -> int
{
    return detail::abs_impl<int>(n);
}

/// \group abs
[[nodiscard]] constexpr auto abs(long n) noexcept -> long
{
    return detail::abs_impl<long>(n);
}

/// \group abs
[[nodiscard]] constexpr auto abs(long long n) noexcept -> long long
{
    return detail::abs_impl<long long>(n);
}

[[nodiscard]] constexpr auto abs(float n) noexcept -> float
{
    return detail::abs_impl<float>(n);
}

/// \group abs
[[nodiscard]] constexpr auto abs(double n) noexcept -> double
{
    return detail::abs_impl<double>(n);
}

/// \group abs
[[nodiscard]] constexpr auto abs(long double n) noexcept -> long double
{
    return detail::abs_impl<long double>(n);
}

[[nodiscard]] constexpr auto fabs(float n) noexcept -> float
{
    return detail::abs_impl<float>(n);
}

[[nodiscard]] constexpr auto fabsf(float n) noexcept -> float
{
    return detail::abs_impl<float>(n);
}

[[nodiscard]] constexpr auto fabs(double n) noexcept -> double
{
    return detail::abs_impl<double>(n);
}

[[nodiscard]] constexpr auto fabs(long double n) noexcept -> long double
{
    return detail::abs_impl<long double>(n);
}

[[nodiscard]] constexpr auto fabsl(long double n) noexcept -> long double
{
    return detail::abs_impl<long double>(n);
}

} // namespace etl

#endif // TETL_MATH_ABS_HPP