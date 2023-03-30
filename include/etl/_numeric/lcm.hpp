// SPDX-License-Identifier: BSL-1.0
#ifndef TETL_NUMERIC_LCM_HPP
#define TETL_NUMERIC_LCM_HPP

#include "etl/_numeric/gcd.hpp"
#include "etl/_type_traits/common_type.hpp"
#include "etl/_type_traits/is_integral.hpp"
#include "etl/_type_traits/is_same.hpp"

namespace etl {

/// \brief Computes the least common multiple of the integers m and n.
///
/// \returns If either m or n is zero, returns zero. Otherwise, returns the
/// least common multiple of |m| and |n|.
template <typename M, typename N>
    requires(is_integral_v<M> and not is_same_v<M, bool> and is_integral_v<N> and not is_same_v<N, bool>)
[[nodiscard]] constexpr auto lcm(M m, N n) -> common_type_t<M, N>
{
    return (m * n) / gcd(m, n);
}

} // namespace etl

#endif // TETL_NUMERIC_LCM_HPP
