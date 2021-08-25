/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_ENUM_HPP
#define TETL_TYPE_TRAITS_IS_ENUM_HPP

#include "etl/_config/builtin_functions.hpp"
#include "etl/_type_traits/bool_constant.hpp"

namespace etl {

/// \group is_enum
template <typename T>
struct is_enum : bool_constant<TETL_BUILTIN_IS_ENUM(T)> {
};

/// \group is_enum
template <typename T>
inline constexpr bool is_enum_v = is_enum<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_ENUM_HPP