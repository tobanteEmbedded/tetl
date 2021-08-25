/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_STANDARD_LAYOUT_HPP
#define TETL_TYPE_TRAITS_IS_STANDARD_LAYOUT_HPP

#include "etl/_config/builtin_functions.hpp"
#include "etl/_type_traits/bool_constant.hpp"

namespace etl {

/// \brief If T is a standard layout type (that is, a scalar type, a
/// standard-layout class, or an array of such type/class, possibly
/// cv-qualified), provides the member constant value equal to true. For any
/// other type, value is false.
template <typename T>
struct is_standard_layout : bool_constant<TETL_BUILTIN_IS_STANDARD_LAYOUT(T)> {
};

template <typename T>
inline constexpr bool is_standard_layout_v = is_standard_layout<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_STANDARD_LAYOUT_HPP