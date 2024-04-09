// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_SIGNED_HPP
#define TETL_TYPE_TRAITS_IS_SIGNED_HPP

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/is_arithmetic.hpp>
#include <etl/_type_traits/remove_cv.hpp>

namespace etl {

namespace detail {
template <typename T>
struct is_signed : false_type { };

template <typename T>
    requires is_arithmetic_v<T>
struct is_signed<T> : bool_constant<T(-1) < T(0)> { };

} // namespace detail

/// \brief If T is an arithmetic type, provides the member constant value equal
/// to true if T(-1) < T(0): this results in true for the floating-point types
/// and the signed integer types, and in false for the unsigned integer types
/// and the type bool. For any other type, value is false.
template <typename T>
struct is_signed : detail::is_signed<remove_cv_t<T>>::type { };

template <typename T>
inline constexpr bool is_signed_v = is_signed<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_SIGNED_HPP
