/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_SIGNED_HPP
#define TETL_TYPE_TRAITS_IS_SIGNED_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/is_arithmetic.hpp"

namespace etl {

namespace detail {
template <typename T, bool = etl::is_arithmetic_v<T>>
struct is_signed : etl::bool_constant<T(-1) < T(0)> {
};

template <typename T>
struct is_signed<T, false> : etl::false_type {
};
} // namespace detail

/// \brief If T is an arithmetic type, provides the member constant value equal
/// to true if T(-1) < T(0): this results in true for the floating-point types
/// and the signed integer types, and in false for the unsigned integer types
/// and the type bool. For any other type, value is false.
template <typename T>
struct is_signed : detail::is_signed<T>::type {
};

template <typename T>
struct is_signed<T const> : detail::is_signed<T>::type {
};
template <typename T>
struct is_signed<T volatile> : detail::is_signed<T>::type {
};
template <typename T>
struct is_signed<T const volatile> : detail::is_signed<T>::type {
};

template <typename T>
inline constexpr bool is_signed_v = is_signed<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_SIGNED_HPP
