// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_FLOATING_POINT_HPP
#define TETL_TYPE_TRAITS_IS_FLOATING_POINT_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/is_same.hpp"
#include "etl/_type_traits/remove_cv.hpp"

namespace etl {

/// \brief Checks whether T is a floating-point type. Provides the member
/// constant value which is equal to true, if T is the type float, double, long
/// double, including any cv-qualified variants. Otherwise, value is equal to
/// false.
///
/// \details The behavior of a program that adds specializations for
/// is_floating_point or is_floating_point_v is undefined.
template <typename T>
struct is_floating_point
    : bool_constant<
          is_same_v<float, remove_cv_t<T>> || is_same_v<double, remove_cv_t<T>>
          || is_same_v<long double, remove_cv_t<T>>> { };

template <typename T>
inline constexpr bool is_floating_point_v = is_floating_point<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_FLOATING_POINT_HPP
