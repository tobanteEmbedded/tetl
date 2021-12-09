/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_COMPLEX_DOUBLE_OR_INT_HPP
#define TETL_COMPLEX_DOUBLE_OR_INT_HPP

#include "etl/_type_traits/is_integral.hpp"
#include "etl/_type_traits/is_same.hpp"

namespace etl {

namespace detail {
template <typename T>
inline constexpr bool double_or_int = is_integral_v<T> || is_same_v<T, double>;
} // namespace detail

} // namespace etl

#endif // TETL_COMPLEX_DOUBLE_OR_INT_HPP