// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_IS_TRIVIALLY_COPY_ASSIGNABLE_HPP
#define TETL_TYPE_TRAITS_IS_TRIVIALLY_COPY_ASSIGNABLE_HPP

#include <etl/_type_traits/add_lvalue_reference.hpp>
#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/is_trivially_assignable.hpp>

namespace etl {

/// \brief If T is not a referenceable type (i.e., possibly cv-qualified void or
/// a function type with a cv-qualifier-seq or a ref-qualifier), provides a
/// member constant value equal to false. Otherwise, provides a member constant
/// value equal to etl::is_trivially_assignable<T&, T const&>::value.
///
/// \details T shall be a complete type, (possibly cv-qualified) void, or an
/// array of unknown bound. Otherwise, the behavior is undefined. If an
/// instantiation of a template above depends, directly or indirectly, on an
/// incomplete type, and that instantiation could yield a different result if
/// that type were hypothetically completed, the behavior is undefined. The
/// behavior of a program that adds specializations for any of the templates
/// described on this page is undefined.
template <typename T>
struct is_trivially_copy_assignable
    : is_trivially_assignable<add_lvalue_reference_t<T>, add_lvalue_reference_t<T const>> { };

template <typename T>
inline constexpr bool is_trivially_copy_assignable_v = is_trivially_copy_assignable<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_TRIVIALLY_COPY_ASSIGNABLE_HPP
