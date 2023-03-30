// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_ADD_LVALUE_REFERENCE_HPP
#define TETL_TYPE_TRAITS_ADD_LVALUE_REFERENCE_HPP

#include "etl/_type_traits/type_identity.hpp"

namespace etl {

namespace detail {
template <typename T>
auto try_add_lvalue_reference(int) -> etl::type_identity<T&>;
template <typename T>
auto try_add_lvalue_reference(...) -> etl::type_identity<T>;

} // namespace detail

/// \brief Creates a lvalue reference type of T.
template <typename T>
struct add_lvalue_reference : decltype(detail::try_add_lvalue_reference<T>(0)) { };

template <typename T>
using add_lvalue_reference_t = typename etl::add_lvalue_reference<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_ADD_LVALUE_REFERENCE_HPP
