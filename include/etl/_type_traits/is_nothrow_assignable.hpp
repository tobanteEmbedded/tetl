// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_IS_NOTHROW_ASSIGNABLE_HPP
#define TETL_TYPE_TRAITS_IS_NOTHROW_ASSIGNABLE_HPP

#include <etl/_type_traits/bool_constant.hpp>
#include <etl/_type_traits/declval.hpp>
#include <etl/_type_traits/is_assignable.hpp>

namespace etl {

/// \brief If the expression etl::declval<T>() = etl::declval<U>() is
/// well-formed in unevaluated context, provides the member constant value equal
/// true. Otherwise, value is false. Access checks are performed as if from a
/// context unrelated to either type.
template <typename T, typename U>
struct is_nothrow_assignable : etl::false_type { };

template <typename T, typename U>
    requires etl::is_assignable_v<T, U>
struct is_nothrow_assignable<T, U> : etl::bool_constant<noexcept(etl::declval<T>() = etl::declval<U>())> { };

template <typename T, typename U>
inline constexpr bool is_nothrow_assignable_v = is_nothrow_assignable<T, U>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_NOTHROW_ASSIGNABLE_HPP
