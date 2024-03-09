// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_FUNCTION_HPP
#define TETL_TYPE_TRAITS_IS_FUNCTION_HPP

#include <etl/_config/all.hpp>

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/is_const.hpp>
#include <etl/_type_traits/is_reference.hpp>

namespace etl {

#if defined(TETL_MSVC)
    // Qualifier applied to function has no meaning
    #pragma warning(disable : 4180)
#endif

template <typename T>
struct is_function : bool_constant<!is_const_v<T const> && !is_reference_v<T>> { };

#if defined(TETL_MSVC)
    // Qualifier applied to function has no meaning
    #pragma warning(default : 4180)
#endif

/// \brief Checks whether T is a function type. Types like etl::function,
/// lambdas, classes with overloaded operator() and pointers to functions don't
/// count as function types. Provides the member constant value which is equal
/// to true, if T is a function type. Otherwise, value is equal to false.
///
/// \details The behavior of a program that adds specializations for is_function
/// or is_function_v is undefined.
template <typename T>
inline constexpr bool is_function_v = is_function<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_FUNCTION_HPP
