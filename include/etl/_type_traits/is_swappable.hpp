// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_SWAPPABLE_HPP
#define TETL_TYPE_TRAITS_IS_SWAPPABLE_HPP

#include <etl/_type_traits/add_lvalue_reference.hpp>
#include <etl/_type_traits/is_swappable_with.hpp>

namespace etl {

// clang-format off

/// \brief If T is not a referenceable type (i.e., possibly cv-qualified void or
/// a function type with a cv-qualifier-seq or a ref-qualifier), provides a
/// member constant value equal to false. Otherwise, provides a member constant
/// value equal to etl::is_swappable_with<T&, T&>::value
template <typename T>
struct is_swappable : is_swappable_with<add_lvalue_reference_t<T>, add_lvalue_reference_t<T>>::type {};

// clang-format on

template <typename T>
inline constexpr bool is_swappable_v = is_swappable<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_SWAPPABLE_HPP
