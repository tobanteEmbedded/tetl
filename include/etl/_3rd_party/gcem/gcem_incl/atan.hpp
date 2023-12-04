/*################################################################################
  ##
  ##   Copyright (C) 2016-2020 Keith O'Hara
  ##
  ##   This file is part of the GCE-Math C++ library.
  ##
  ##   Licensed under the Apache License, Version 2.0 (the "License");
  ##   you may not use this file except in compliance with the License.
  ##   You may obtain a copy of the License at
  ##
  ##       http://www.apache.org/licenses/LICENSE-2.0
  ##
  ##   Unless required by applicable law or agreed to in writing, software
  ##   distributed under the License is distributed on an "AS IS" BASIS,
  ##   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  ##   See the License for the specific language governing permissions and
  ##   limitations under the License.
  ##
  ################################################################################*/

/*
 * compile-time arctangent function
 */

// see
// http://functions.wolfram.com/ElementaryFunctions/ArcTan/10/0001/
// http://functions.wolfram.com/ElementaryFunctions/ArcTan/06/01/06/01/0002/

#ifndef GCEM_atan_HPP
#define GCEM_atan_HPP

namespace internal {

// Series

template <typename T>
constexpr auto atan_series_order_calc(T const x, T const xPow, uint_t const order) noexcept -> T
{
    return (T(1) / (T((order - 1) * 4 - 1) * xPow) - T(1) / (T((order - 1) * 4 + 1) * xPow * x));
}

template <typename T>
constexpr auto atan_series_order(T const x, T const xPow, uint_t const order, uint_t const maxOrder) noexcept -> T
{
    return static_cast<T>(
        order == 1 ? GCEM_HALF_PI - T(1) / x + atan_series_order(x * x, pow(x, 3), order + 1, maxOrder) :
                   // NOTE: x changes to x*x for order > 1
            order < maxOrder
            ? atan_series_order_calc(x, xPow, order) + atan_series_order(x, xPow * x * x, order + 1, maxOrder)
            :
            // order == max_order
            atan_series_order_calc(x, xPow, order));
}

template <typename T>
constexpr auto atan_series_main(T const x) noexcept -> T
{
    return static_cast<T>(x < T(3) ? atan_series_order(x, x, 1U, 10U) : // O(1/x^39)
                              x < T(4) ? atan_series_order(x, x, 1U, 9U)
                                       : // O(1/x^35)
                              x < T(5) ? atan_series_order(x, x, 1U, 8U)
                                       : // O(1/x^31)
                              x < T(7) ? atan_series_order(x, x, 1U, 7U)
                                       : // O(1/x^27)
                              x < T(11) ? atan_series_order(x, x, 1U, 6U)
                                        : // O(1/x^23)
                              x < T(25) ? atan_series_order(x, x, 1U, 5U)
                                        : // O(1/x^19)
                              x < T(100) ? atan_series_order(x, x, 1U, 4U)
                                         : // O(1/x^15)
                              x < T(1000) ? atan_series_order(x, x, 1U, 3U)
                                          :                     // O(1/x^11)
                              atan_series_order(x, x, 1U, 2U)); // O(1/x^7)
}

// CF

template <typename T>
constexpr auto atan_cf_recur(T const xx, uint_t const depth, uint_t const maxDepth) noexcept -> T
{
    return (depth < maxDepth ? // if
                T(2 * depth - 1) + depth * depth * xx / atan_cf_recur(xx, depth + 1, maxDepth)
                             :
                             // else
                T(2 * depth - 1));
}

template <typename T>
constexpr auto atan_cf_main(T const x) noexcept -> T
{
    return (x < T(0.5)   ? x / atan_cf_recur(x * x, 1U, 15U)
            : x < T(1)   ? x / atan_cf_recur(x * x, 1U, 25U)
            : x < T(1.5) ? x / atan_cf_recur(x * x, 1U, 35U)
            : x < T(2)   ? x / atan_cf_recur(x * x, 1U, 45U)
                         : x / atan_cf_recur(x * x, 1U, 52U));
}

//

template <typename T>
constexpr auto atan_begin(T const x) noexcept -> T
{
    return (x > T(2.5) ? atan_series_main(x) : atan_cf_main(x));
}

template <typename T>
constexpr auto atan_check(T const x) noexcept -> T
{
    return ( // NaN check
        is_nan(x) ? etl::numeric_limits<T>::quiet_NaN() :
                  // indistinguishable from zero
            etl::numeric_limits<T>::epsilon() > abs(x) ? T(0)
                                                       :
                                                       // negative or positive
            x < T(0) ? -atan_begin(-x)
                     : atan_begin(x));
}

} // namespace internal

/**
 * Compile-time arctangent function
 *
 * @param x a real-valued input.
 * @return the inverse tangent function using \f[ \text{atan}(x) = \dfrac{x}{1 +
 * \dfrac{x^2}{3 + \dfrac{4x^2}{5 + \dfrac{9x^2}{7 + \ddots}}}} \f]
 */

template <typename T>
constexpr auto atan(T const x) noexcept -> return_t<T>
{
    return internal::atan_check(static_cast<return_t<T>>(x));
}

#endif
