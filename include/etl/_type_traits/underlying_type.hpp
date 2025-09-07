// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_IS_UNDERLYING_TYPE_HPP
#define TETL_TYPE_TRAITS_IS_UNDERLYING_TYPE_HPP

#include <etl/_config/all.hpp>

#include <etl/_type_traits/is_enum.hpp>

namespace etl {

namespace detail {
template <typename T>
struct underlying_type { };

template <typename T>
    requires is_enum_v<T>
struct underlying_type<T> {
    using type = __underlying_type(T);
};

} // namespace detail

/// The underlying type of an enum.
/// \ingroup type_traits
template <typename T>
struct underlying_type : detail::underlying_type<T> { };

/// \ingroup type_traits
template <typename T>
using underlying_type_t = typename underlying_type<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_UNDERLYING_TYPE_HPP
