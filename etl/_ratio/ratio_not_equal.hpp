/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_RATIO_NOT_EQUAL_HPP
#define TETL_RATIO_NOT_EQUAL_HPP

#include "etl/_ratio/ratio.hpp"
#include "etl/_type_traits/bool_constant.hpp"

namespace etl {

/// \brief Compares two ratio objects for equality at compile-time. If the
/// ratios R1 and R2 are not equal, provides the member constant value equal
/// true. Otherwise, value is false.
template <typename R1, typename R2>
struct ratio_not_equal : bool_constant<!ratio_equal_v<R1, R2>> {
};

template <typename R1, typename R2>
inline constexpr bool ratio_not_equal_v = ratio_not_equal<R1, R2>::value;

} // namespace etl

#endif // TETL_RATIO_NOT_EQUAL_HPP