/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_NOTHROW_DESTRUCTIBLE_HPP
#define TETL_TYPE_TRAITS_IS_NOTHROW_DESTRUCTIBLE_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/is_destructible.hpp"

namespace etl {

namespace detail {
template <bool, typename Type>
struct is_nothrow_destructible_helper;

template <typename Type>
struct is_nothrow_destructible_helper<false, Type> : etl::false_type {
};

template <typename Type>
struct is_nothrow_destructible_helper<true, Type>
    : etl::bool_constant<noexcept(etl::declval<Type>().~Type())> {
};
} // namespace detail

/// https://en.cppreference.com/w/cpp/types/is_destructible
/// \group is_nothrow_destructible
template <typename Type>
struct is_nothrow_destructible
    : detail::is_nothrow_destructible_helper<is_destructible_v<Type>, Type> {
};

/// \exclude
template <typename Type, size_t N>
struct is_nothrow_destructible<Type[N]> : is_nothrow_destructible<Type> {
};

/// \exclude
template <typename Type>
struct is_nothrow_destructible<Type&> : true_type {
};

/// \exclude
template <typename Type>
struct is_nothrow_destructible<Type&&> : true_type {
};

/// \group is_nothrow_destructible
template <typename T>
inline constexpr bool is_nothrow_destructible_v
    = is_nothrow_destructible<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_NOTHROW_DESTRUCTIBLE_HPP