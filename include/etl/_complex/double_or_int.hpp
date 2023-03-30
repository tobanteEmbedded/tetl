// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPLEX_DOUBLE_OR_INT_HPP
#define TETL_COMPLEX_DOUBLE_OR_INT_HPP

#include "etl/_type_traits/is_integral.hpp"
#include "etl/_type_traits/is_same.hpp"

namespace etl::detail {

template <typename T>
inline constexpr bool double_or_int = is_integral_v<T> || is_same_v<T, double>;

} // namespace etl::detail

#endif // TETL_COMPLEX_DOUBLE_OR_INT_HPP
