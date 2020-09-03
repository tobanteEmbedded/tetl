/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

/**
 * @example numeric.cpp
 */

#ifndef TAETL_NUMERIC_HPP
#define TAETL_NUMERIC_HPP

#include "definitions.hpp"
#include "limits.hpp"
#include "type_traits.hpp"

namespace etl
{
/**
 * @brief Computes the sum of the given value init and the elements in the range
 * [first, last). Uses operator+ to sum up the elements.
 */
template <class InputIt, class Type>
[[nodiscard]] constexpr auto accumulate(InputIt first, InputIt last,
                                        Type init) noexcept -> Type
{
    for (; first != last; ++first)
    {
        init = init + *first;  // etl::move since C++20
    }
    return init;
}

/**
 * @brief Computes the sum of the given value init and the elements in the range
 * [first, last). Uses the BinaryOperation to sum up the elements.
 */
template <class InputIt, class Type, class BinaryOperation>
[[nodiscard]] constexpr auto accumulate(InputIt first, InputIt last, Type init,
                                        BinaryOperation op) noexcept -> Type
{
    for (; first != last; ++first)
    {
        init = op(init, *first);  // etl::move since C++20
    }
    return init;
}

/**
 * @brief Returns the absolute value.
 */
template <typename Type>
[[nodiscard]] constexpr auto abs(Type input) noexcept -> Type
{
    if (input < 0) { return static_cast<Type>(-input); }
    return input;
}

/**
 * @brief Computes the greatest common divisor of the integers m and n.
 *
 * @todo Actual return type is etl::common_type. Needs to be implemented.
 */
template <typename M, typename N>
[[nodiscard]] constexpr auto gcd(M m, N n) noexcept
{
    if (n == 0) { return m; }
    return gcd(n, m % n);
}

/**
 * @brief Returns half the sum of a + b. If the sum is odd, the result is
 * rounded towards a.
 * @detail T is arithmentic type other than bool
 */
template <typename Integer>
constexpr auto midpoint(Integer a, Integer b) noexcept
    -> etl::enable_if_t<etl::is_integral_v<Integer>, Integer>
{
    using U  = etl::make_unsigned_t<Integer>;
    int sign = 1;
    auto m   = static_cast<U>(a);
    auto M   = static_cast<U>(b);
    if (a > b)
    {
        sign = -1;
        m    = static_cast<U>(b);
        M    = static_cast<U>(a);
    }
    return static_cast<Integer>(
        a + static_cast<Integer>(sign * static_cast<Integer>(U(M - m) >> 1)));
}

template <typename Float>
constexpr auto midpoint(Float a, Float b) noexcept
    -> etl::enable_if_t<etl::is_floating_point_v<Float>, Float>
{
    auto const lo = etl::numeric_limits<Float>::min() * 2;
    auto const hi = etl::numeric_limits<Float>::max() / 2;

    if (etl::abs(a) <= hi && etl::abs(b) <= hi) { return (a + b) / 2; }

    if (etl::abs(a) < lo) { return a + b / 2; }

    if (etl::abs(b) < lo) { return a / 2 + b; }

    return a / 2 + b / 2;
}

template <typename Pointer>
constexpr auto midpoint(Pointer a, Pointer b) noexcept
    -> enable_if_t<is_pointer_v<Pointer>, Pointer>
{
    return a + midpoint(ptrdiff_t {0}, b - a);
}

}  // namespace etl

#endif  // TAETL_NUMERIC_HPP