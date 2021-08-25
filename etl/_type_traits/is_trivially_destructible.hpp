/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_TRVIALLY_DETRUCTIBLE_HPP
#define TETL_TYPE_TRAITS_IS_TRVIALLY_DETRUCTIBLE_HPP

#include "etl/_config/builtin_functions.hpp"
#include "etl/_type_traits/bool_constant.hpp"

namespace etl {

/// \brief Storage occupied by trivially destructible objects may be reused
/// without calling the destructor.
///
/// https://en.cppreference.com/w/cpp/types/is_destructible
template <typename T>
struct is_trivially_destructible
    : bool_constant<TETL_BUILTIN_IS_TRIVIAL_DESTRUCTIBLE(T)> {
};

template <typename T>
inline constexpr auto is_trivially_destructible_v
    = is_trivially_destructible<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_TRVIALLY_DETRUCTIBLE_HPP