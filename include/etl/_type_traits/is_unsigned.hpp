/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_UNSIGNED_HPP
#define TETL_TYPE_TRAITS_IS_UNSIGNED_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/is_arithmetic.hpp"

namespace etl {

namespace detail {
template <typename T, bool = etl::is_arithmetic_v<T>>
struct is_unsigned : etl::bool_constant<T(0) < T(-1)> { };

template <typename T>
struct is_unsigned<T, false> : etl::false_type { };
} // namespace detail

/// \brief If T is an arithmetic type, provides the member constant value equal
/// to true if T(0) < T(-1): this results in true for the unsigned integer types
/// and the type bool and in false for the signed integer types and the
/// floating-point types. For any other type, value is false. The behavior of a
/// program that adds specializations for is_unsigned or is_unsigned_v (since
/// C++17) is undefined.
template <typename T>
struct is_unsigned : detail::is_unsigned<T>::type { };

template <typename T>
struct is_unsigned<T const> : detail::is_unsigned<T>::type { };
template <typename T>
struct is_unsigned<T volatile> : detail::is_unsigned<T>::type { };
template <typename T>
struct is_unsigned<T const volatile> : detail::is_unsigned<T>::type { };

template <typename T>
inline constexpr bool is_unsigned_v = etl::is_unsigned<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_UNSIGNED_HPP
