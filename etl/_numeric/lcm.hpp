/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#ifndef TETL_NUMERIC_LCM_HPP
#define TETL_NUMERIC_LCM_HPP

#include "etl/_numeric/gcd.hpp"
#include "etl/_type_traits/common_type.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"
#include "etl/_type_traits/is_same.hpp"

namespace etl {

/// \brief Computes the least common multiple of the integers m and n.
///
/// \returns If either m or n is zero, returns zero. Otherwise, returns the
/// least common multiple of |m| and |n|.
// clang-format off
template <typename M, typename N,
    enable_if_t<
        is_integral_v<M>
        && !is_same_v<M, bool>
        && is_integral_v<N>
        && !is_same_v<N, bool>,
    int> = 0>
// clang-format on
[[nodiscard]] constexpr auto lcm(M m, N n) -> common_type_t<M, N>
{
    return (m * n) / gcd(m, n);
}
} // namespace etl

#endif // TETL_NUMERIC_LCM_HPP
