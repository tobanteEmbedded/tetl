/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_TRIVIALLY_CONSTRUCTIBLE_HPP
#define TETL_TYPE_TRAITS_IS_TRIVIALLY_CONSTRUCTIBLE_HPP

#include "etl/_config/builtin_functions.hpp"
#include "etl/_type_traits/bool_constant.hpp"

namespace etl {

/// \brief The variable definition does not call any operation that is not
/// trivial. For the purposes of this check, the call to etl::declval is
/// considered trivial.
template <typename T, typename... Args>
struct is_trivially_constructible
    : bool_constant<TETL_BUILTIN_IS_TRIVIAL_CONSTRUCTIBLE(T)> {
};

template <typename T, typename... Args>
inline constexpr bool is_trivially_constructible_v
    = is_trivially_constructible<T, Args...>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_TRIVIALLY_CONSTRUCTIBLE_HPP