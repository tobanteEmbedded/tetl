/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_ASSIGNABLE_HPP
#define TETL_TYPE_TRAITS_IS_ASSIGNABLE_HPP

#include "etl/_config/builtin_functions.hpp"
#include "etl/_type_traits/bool_constant.hpp"

namespace etl {

/// \brief If the expression etl::declval<T>() = etl::declval<U>() is
/// well-formed in unevaluated context, provides the member constant value equal
/// true. Otherwise, value is false. Access checks are performed as if from a
/// context unrelated to either type.
template <typename T, typename U>
struct is_assignable : bool_constant<TETL_BUILTIN_IS_ASSIGNABLE(T, U)> {
};

template <typename T, typename U>
inline constexpr bool is_assignable_v = is_assignable<T, U>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_ASSIGNABLE_HPP