// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_ARITHMETIC_HPP
#define TETL_TYPE_TRAITS_IS_ARITHMETIC_HPP

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/is_floating_point.hpp>
#include <etl/_type_traits/is_integral.hpp>

namespace etl {

/// \brief If T is an arithmetic type (that is, an integral type or a
/// floating-point type) or a cv-qualified version thereof, provides the member
/// constant value equal true. For any other type, value is false. The behavior
/// of a program that adds specializations for is_arithmetic or is_arithmetic_v
/// (since C++17) is undefined.
template <typename T>
struct is_arithmetic : etl::bool_constant<etl::is_integral_v<T> or etl::is_floating_point_v<T>> { };

template <typename T>
inline constexpr bool is_arithmetic_v = etl::is_integral_v<T> or etl::is_floating_point_v<T>;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_ARITHMETIC_HPP
