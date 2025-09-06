// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_IS_COMPOUND_HPP
#define TETL_TYPE_TRAITS_IS_COMPOUND_HPP

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/is_fundamental.hpp>

namespace etl {

/// \brief If T is a compound type (that is, array, function, object pointer,
/// function pointer, member object pointer, member function pointer, reference,
/// class, union, or enumeration, including any cv-qualified variants), provides
/// the member constant value equal true. For any other type, value is false.
template <typename T>
struct is_compound : bool_constant<not is_fundamental_v<T>> { };

template <typename T>
inline constexpr bool is_compound_v = not is_fundamental_v<T>;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_COMPOUND_HPP
