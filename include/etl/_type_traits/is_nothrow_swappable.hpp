/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_NOTHROW_SWAPPABLE_HPP
#define TETL_TYPE_TRAITS_IS_NOTHROW_SWAPPABLE_HPP

#include "etl/_type_traits/add_lvalue_reference.hpp"
#include "etl/_type_traits/is_nothrow_swappable_with.hpp"

namespace etl {

// clang-format off

/// \brief If T is not a referenceable type (i.e., possibly cv-qualified void or
/// a function type with a cv-qualifier-seq or a ref-qualifier), provides a
/// member constant value equal to false. Otherwise, provides a member constant
/// value equal to etl::is_nothrow_swappable_with<T&, T&>::value
template <typename T>
struct is_nothrow_swappable : is_nothrow_swappable_with<add_lvalue_reference_t<T>, add_lvalue_reference_t<T>>::type {};

template <typename T>
inline constexpr bool is_nothrow_swappable_v = is_nothrow_swappable<T>::value;

// clang-format on

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_NOTHROW_SWAPPABLE_HPP
