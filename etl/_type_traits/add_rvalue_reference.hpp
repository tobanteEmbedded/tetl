/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_ADD_RVALUE_REFERENCE_HPP
#define TETL_TYPE_TRAITS_ADD_RVALUE_REFERENCE_HPP

#include "etl/_type_traits/type_identity.hpp"

namespace etl {

namespace detail {
template <typename T>
auto try_add_rvalue_reference(int) -> etl::type_identity<T&&>;
template <typename T>
auto try_add_rvalue_reference(...) -> etl::type_identity<T>;
} // namespace detail

/// \brief Creates a rvalue reference type of T.
template <typename T>
struct add_rvalue_reference : decltype(detail::try_add_rvalue_reference<T>(0)) {
};

template <typename T>
using add_rvalue_reference_t = typename etl::add_rvalue_reference<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_ADD_RVALUE_REFERENCE_HPP