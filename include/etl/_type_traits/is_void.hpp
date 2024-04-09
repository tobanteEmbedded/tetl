// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_VOID_HPP
#define TETL_TYPE_TRAITS_IS_VOID_HPP

#include <etl/_type_traits/is_same.hpp>
#include <etl/_type_traits/remove_cv.hpp>

namespace etl {

/// \brief Define a member typedef only if a boolean constant is true.
template <typename T>
struct is_void : is_same<void, remove_cv_t<T>> { };

template <typename T>
inline constexpr bool is_void_v = is_same_v<void, remove_cv_t<T>>;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_VOID_HPP
