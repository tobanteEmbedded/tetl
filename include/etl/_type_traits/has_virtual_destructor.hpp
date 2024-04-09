// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_HAS_VIRTUAL_DESTRUCTOR_HPP
#define TETL_TYPE_TRAITS_HAS_VIRTUAL_DESTRUCTOR_HPP

#include <etl/_config/all.hpp>

#include <etl/_type_traits/bool_constant.hpp>

namespace etl {

/// https://en.cppreference.com/w/cpp/types/has_virtual_destructor
/// \ingroup type_traits
template <typename T>
struct has_virtual_destructor : bool_constant<__has_virtual_destructor(T)> { };

/// \relates has_virtual_destructor
/// \ingroup type_traits
template <typename T>
inline constexpr auto has_virtual_destructor_v = __has_virtual_destructor(T);

} // namespace etl

#endif // TETL_TYPE_TRAITS_HAS_VIRTUAL_DESTRUCTOR_HPP
