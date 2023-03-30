// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FUNCTIONAL_IS_TRANSPARENT_HPP
#define TETL_FUNCTIONAL_IS_TRANSPARENT_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/is_same.hpp"
#include "etl/_type_traits/void_t.hpp"

namespace etl::detail {

template <typename T, typename = void>
inline constexpr bool is_transparent_v = false;

template <typename T>
inline constexpr bool is_transparent_v<T, void_t<typename T::is_transparent>> = true;

template <typename T>
struct is_transparent : bool_constant<is_transparent_v<T>> { };

} // namespace etl::detail

#endif // TETL_FUNCTIONAL_IS_TRANSPARENT_HPP
