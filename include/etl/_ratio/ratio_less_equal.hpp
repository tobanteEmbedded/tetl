// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_RATIO_LESS_EQUAL_HPP
#define TETL_RATIO_LESS_EQUAL_HPP

#include <etl/_ratio/ratio.hpp>
#include <etl/_type_traits/bool_constant.hpp>

namespace etl {

/// \brief Compares two ratio objects for equality at compile-time. If the ratio
/// R1 is less than or equal to the ratio R2, provides the member constant value
/// equal true. Otherwise, value is false.
/// \ingroup ratio
template <typename R1, typename R2>
struct ratio_less_equal : bool_constant<(R1::num * R2::den <= R2::num * R1::den)> { };

/// \ingroup ratio
template <typename R1, typename R2>
inline constexpr bool ratio_less_equal_v = ratio_less_equal<R1, R2>::value;

} // namespace etl

#endif // TETL_RATIO_LESS_EQUAL_HPP
