/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_IMPLICIT_DEFAULT_CONSTRUCTIBLE_HPP
#define TETL_TYPE_TRAITS_IS_IMPLICIT_DEFAULT_CONSTRUCTIBLE_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/is_default_constructible.hpp"

namespace etl {

template <typename T>
void test_implicit_default_constructible(T);

template <typename T, typename = void,
    typename = typename etl::is_default_constructible<T>::type>
struct is_implicit_default_constructible : false_type {
};

template <typename T>
struct is_implicit_default_constructible<T,
    decltype(test_implicit_default_constructible<T const&>({})), true_type>
    : true_type {
};

template <typename T>
struct is_implicit_default_constructible<T,
    decltype(test_implicit_default_constructible<T const&>({})), false_type>
    : false_type {
};

template <typename T>
inline constexpr auto is_implicit_default_constructible_v
    = is_implicit_default_constructible<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_IMPLICIT_DEFAULT_CONSTRUCTIBLE_HPP