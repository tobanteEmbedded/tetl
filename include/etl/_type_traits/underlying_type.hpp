// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_UNDERLYING_TYPE_HPP
#define TETL_TYPE_TRAITS_IS_UNDERLYING_TYPE_HPP

#include <etl/_config/all.hpp>

#include "etl/_type_traits/is_enum.hpp"

namespace etl {

namespace detail {
template <typename T, bool = is_enum_v<T>>
struct underlying_type_impl {
    using type = __underlying_type(T);
};

template <typename T>
struct underlying_type_impl<T, false> { };

} // namespace detail

/// \brief The underlying type of an enum.
template <typename T>
struct underlying_type : detail::underlying_type_impl<T> { };

template <typename T>
using underlying_type_t = typename etl::underlying_type<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_UNDERLYING_TYPE_HPP
