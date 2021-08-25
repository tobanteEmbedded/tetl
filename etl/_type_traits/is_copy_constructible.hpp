/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_COPY_CONSTRUCTIBLE_HPP
#define TETL_TYPE_TRAITS_IS_COPY_CONSTRUCTIBLE_HPP

#include "etl/_type_traits/add_const.hpp"
#include "etl/_type_traits/add_lvalue_reference.hpp"
#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/is_constructible.hpp"

namespace etl {

/// \brief If T is not a referenceable type (i.e., possibly cv-qualified void or
/// a function type with a cv-qualifier-seq or a ref-qualifier), provides a
/// member constant value equal to false. Otherwise, provides a member constant
/// value equal to etl::is_constructible<T, T const&>::value.
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
struct is_copy_constructible
    : is_constructible<T, add_lvalue_reference_t<add_const_t<T>>> {
};

template <typename T>
inline constexpr bool is_copy_constructible_v = is_copy_constructible<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_COPY_CONSTRUCTIBLE_HPP