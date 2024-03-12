// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_ASSIGNABLE_HPP
#define TETL_TYPE_TRAITS_IS_ASSIGNABLE_HPP

#include <etl/_config/all.hpp>

#include "etl/_type_traits/bool_constant.hpp"

namespace etl {

/// \brief If the expression etl::declval<T>() = etl::declval<U>() is
/// well-formed in unevaluated context, provides the member constant value equal
/// true. Otherwise, value is false. Access checks are performed as if from a
/// context unrelated to either type.
template <typename T, typename U>
struct is_assignable : etl::bool_constant<__is_assignable(T, U)> { };

template <typename T, typename U>
inline constexpr bool is_assignable_v = __is_assignable(T, U);

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_ASSIGNABLE_HPP
