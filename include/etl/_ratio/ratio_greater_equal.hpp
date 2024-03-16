// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RATIO_GREATER_EQUAL_HPP
#define TETL_RATIO_GREATER_EQUAL_HPP

#include <etl/_ratio/ratio.hpp>
#include <etl/_type_traits/bool_constant.hpp>

namespace etl {

/// \brief Compares two ratio objects for equality at compile-time. If the ratio
/// R1 is greater than or equal to the ratio R2, provides the member constant
/// value equal true. Otherwise, value is false.
template <typename R1, typename R2>
struct ratio_greater_equal : bool_constant<(R1::num * R2::den >= R2::num * R1::den)> { };

template <typename R1, typename R2>
inline constexpr bool ratio_greater_equal_v = ratio_greater_equal<R1, R2>::value;

} // namespace etl

#endif // TETL_RATIO_GREATER_EQUAL_HPP
