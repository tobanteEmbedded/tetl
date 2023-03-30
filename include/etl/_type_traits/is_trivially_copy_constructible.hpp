// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_TRIVIAL_COPY_CONSTRUCTIBLE_HPP
#define TETL_TYPE_TRAITS_IS_TRIVIAL_COPY_CONSTRUCTIBLE_HPP

#include "etl/_type_traits/add_const.hpp"
#include "etl/_type_traits/add_lvalue_reference.hpp"
#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/is_trivially_constructible.hpp"

namespace etl {

/// \brief Same as copy, but uses etl::is_trivially_constructible<T, T const&>.
///
/// \details T shall be a complete type, (possibly cv-qualified) void, or an
/// array of unknown bound. Otherwise, the behavior is undefined. If an
/// instantiation of a template above depends, directly or indirectly, on an
/// incomplete type, and that instantiation could yield a different result if
/// that type were hypothetically completed, the behavior is undefined.
///
/// The behavior of a program that adds specializations for any of the templates
/// described on this page is undefined.
template <typename T>
struct is_trivially_copy_constructible : is_trivially_constructible<T, add_lvalue_reference_t<add_const_t<T>>> { };

template <typename T>
inline constexpr bool is_trivially_copy_constructible_v = is_trivially_copy_constructible<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_TRIVIAL_COPY_CONSTRUCTIBLE_HPP
