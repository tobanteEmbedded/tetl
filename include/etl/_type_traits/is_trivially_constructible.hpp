// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_TRIVIALLY_CONSTRUCTIBLE_HPP
#define TETL_TYPE_TRAITS_IS_TRIVIALLY_CONSTRUCTIBLE_HPP

#include <etl/_config/all.hpp>

#include <etl/_type_traits/bool_constant.hpp>

namespace etl {

/// \brief The variable definition does not call any operation that is not
/// trivial. For the purposes of this check, the call to etl::declval is
/// considered trivial.
template <typename T, typename... Args>
struct is_trivially_constructible : bool_constant<__is_trivially_constructible(T)> { };

template <typename T, typename... Args>
inline constexpr bool is_trivially_constructible_v = is_trivially_constructible<T, Args...>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_TRIVIALLY_CONSTRUCTIBLE_HPP
