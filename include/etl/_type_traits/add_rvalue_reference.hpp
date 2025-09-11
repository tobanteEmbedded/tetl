// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_ADD_RVALUE_REFERENCE_HPP
#define TETL_TYPE_TRAITS_ADD_RVALUE_REFERENCE_HPP

#include <etl/_type_traits/type_identity.hpp>

namespace etl {

namespace detail {

template <typename T>
auto try_add_rvalue_reference(int) -> type_identity<T&&>;

template <typename T>
auto try_add_rvalue_reference(...) -> type_identity<T>;

} // namespace detail

/// \brief Creates a rvalue reference type of T.
/// \headerfile etl/type_traits.hpp
/// \ingroup type_traits
template <typename T>
struct add_rvalue_reference : decltype(detail::try_add_rvalue_reference<T>(0)) { };

/// \relates add_rvalue_reference
/// \ingroup type_traits
template <typename T>
using add_rvalue_reference_t = typename add_rvalue_reference<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_ADD_RVALUE_REFERENCE_HPP
