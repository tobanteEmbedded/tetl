// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RATIO_EQUAL_HPP
#define TETL_RATIO_EQUAL_HPP

#include <etl/_ratio/ratio.hpp>
#include <etl/_type_traits/bool_constant.hpp>

namespace etl {

/// \brief Compares two ratio objects for equality at compile-time. If the
/// ratios R1 and R2 are equal, provides the member constant value equal true.
/// Otherwise, value is false.
/// \ingroup ratio
template <typename R1, typename R2>
struct ratio_equal : bool_constant<R1::num == R2::num && R1::den == R2::den> { };

/// \relates ratio_equal
/// \ingroup ratio
template <typename R1, typename R2>
inline constexpr bool ratio_equal_v = ratio_equal<R1, R2>::value;

} // namespace etl

#endif // TETL_RATIO_EQUAL_HPP
