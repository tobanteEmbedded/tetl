// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_ADD_POINTER_HPP
#define TETL_TYPE_TRAITS_ADD_POINTER_HPP

#include "etl/_type_traits/remove_reference.hpp"
#include "etl/_type_traits/type_identity.hpp"

namespace etl {

namespace detail {
template <typename T>
auto try_add_pointer(int) -> etl::type_identity<etl::remove_reference_t<T>*>;
template <typename T>
auto try_add_pointer(...) -> etl::type_identity<T>;

} // namespace detail

/// \brief If T is a reference type, then provides the member typedef type which
/// is a pointer to the referred type. Otherwise, if T names an object type, a
/// function type that is not cv- or ref-qualified, or a (possibly cv-qualified)
/// void type, provides the member typedef type which is the type T*. Otherwise
/// (if T is a cv- or ref-qualified function type), provides the member typedef
/// type which is the type T. The behavior of a program that adds
/// specializations for add_pointer is undefined.
template <typename T>
struct add_pointer : decltype(detail::try_add_pointer<T>(0)) { };

template <typename T>
using add_pointer_t = typename etl::add_pointer<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_ADD_POINTER_HPP
