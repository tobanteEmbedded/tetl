// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_HAS_UNIQUE_OBJECT_REPRESENTATION_HPP
#define TETL_TYPE_TRAITS_HAS_UNIQUE_OBJECT_REPRESENTATION_HPP

#include <etl/_config/all.hpp>

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/remove_all_extents.hpp>
#include <etl/_type_traits/remove_cv.hpp>

namespace etl {

/// \brief If T is TriviallyCopyable and if any two objects of type T with the
/// same value have the same object representation, provides the member constant
/// value equal true. For any other type, value is false.
///
/// \details For the purpose of this trait, two arrays have the same value if
/// their elements have the same values, two non-union classes have the same
/// value if their direct subobjects have the same value, and two unions have
/// the same value if they have the same active member and the value of that
/// member is the same. It is implementation-defined which scalar types satisfy
/// this trait, but unsigned (until C++20) integer types that do not use padding
/// bits are guaranteed to have unique object representations. The behavior is
/// undefined if T is an incomplete type other than (possibly cv-qualified) void
/// or array of unknown bound. The behavior of a program that adds
/// specializations for has_unique_object_representations or
/// has_unique_object_representations_v is undefined.
template <typename T>
struct has_unique_object_representations
    : bool_constant<__has_unique_object_representations(remove_cv_t<remove_all_extents_t<T>>)> { };

template <typename T>
inline constexpr bool has_unique_object_representations_v = has_unique_object_representations<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_HAS_UNIQUE_OBJECT_REPRESENTATION_HPP
