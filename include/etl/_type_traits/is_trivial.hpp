/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_TRIVIAL_HPP
#define TETL_TYPE_TRAITS_IS_TRIVIAL_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/is_trivially_copyable.hpp"
#include "etl/_type_traits/is_trivially_default_constructible.hpp"

namespace etl {

/// \brief If T is TrivialType (that is, a scalar type, a trivially copyable
/// class with a trivial default constructor, or array of such type/class,
/// possibly cv-qualified), provides the member constant value equal to true.
/// For any other type, value is false.
///
/// https://en.cppreference.com/w/cpp/types/is_trivial
template <typename T>
struct is_trivial : bool_constant<is_trivially_copyable_v<T> and is_trivially_default_constructible_v<T>> { };

template <typename T>
inline constexpr bool is_trivial_v = is_trivial<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_TRIVIAL_HPP
