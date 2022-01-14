/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_HAS_VIRTUAL_DESTRUCTOR_HPP
#define TETL_TYPE_TRAITS_HAS_VIRTUAL_DESTRUCTOR_HPP

#include "etl/_config/all.hpp"

#include "etl/_type_traits/bool_constant.hpp"

namespace etl {

/// https://en.cppreference.com/w/cpp/types/has_virtual_destructor
template <typename T>
struct has_virtual_destructor : bool_constant<__has_virtual_destructor(T)> {
};

/// https://en.cppreference.com/w/cpp/types/has_virtual_destructor
template <typename T>
inline constexpr auto has_virtual_destructor_v = __has_virtual_destructor(T);

} // namespace etl

#endif // TETL_TYPE_TRAITS_HAS_VIRTUAL_DESTRUCTOR_HPP