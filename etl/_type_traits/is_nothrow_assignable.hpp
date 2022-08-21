/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_NOTHROW_ASSIGNABLE_HPP
#define TETL_TYPE_TRAITS_IS_NOTHROW_ASSIGNABLE_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/is_assignable.hpp"

namespace etl {

namespace detail {
template <typename T, typename U>
struct is_nothrow_assignable_helper : etl::bool_constant<noexcept(etl::declval<T>() = etl::declval<U>())> {
};
} // namespace detail

/// \brief If the expression etl::declval<T>() = etl::declval<U>() is
/// well-formed in unevaluated context, provides the member constant value equal
/// true. Otherwise, value is false. Access checks are performed as if from a
/// context unrelated to either type.
template <typename T, typename U>
struct is_nothrow_assignable
    : bool_constant<is_assignable_v<T, U> && detail::is_nothrow_assignable_helper<T, U>::value> {
};

template <typename T, typename U>
inline constexpr bool is_nothrow_assignable_v = is_nothrow_assignable<T, U>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_NOTHROW_ASSIGNABLE_HPP
