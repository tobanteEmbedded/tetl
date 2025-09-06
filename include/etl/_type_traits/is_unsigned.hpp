// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_IS_UNSIGNED_HPP
#define TETL_TYPE_TRAITS_IS_UNSIGNED_HPP

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/is_arithmetic.hpp>
#include <etl/_type_traits/remove_cv.hpp>

namespace etl {

namespace detail {

template <typename T>
struct is_unsigned : false_type { };

template <typename T>
    requires is_arithmetic_v<T>
struct is_unsigned<T> : bool_constant<T(0) < T(-1)> { };

} // namespace detail

/// \brief If T is an arithmetic type, provides the member constant value equal
/// to true if T(0) < T(-1): this results in true for the unsigned integer types
/// and the type bool and in false for the signed integer types and the
/// floating-point types. For any other type, value is false. The behavior of a
/// program that adds specializations for is_unsigned or is_unsigned_v (since
/// C++17) is undefined.
template <typename T>
struct is_unsigned : detail::is_unsigned<remove_cv_t<T>>::type { };

template <typename T>
inline constexpr bool is_unsigned_v = is_unsigned<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_UNSIGNED_HPP
