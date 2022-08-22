

/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_UTILITY_MOVE_IF_NOEXCEPT_HPP
#define TETL_UTILITY_MOVE_IF_NOEXCEPT_HPP

#include "etl/_type_traits/conditional.hpp"
#include "etl/_type_traits/is_copy_constructible.hpp"
#include "etl/_type_traits/is_nothrow_move_constructible.hpp"
#include "etl/_utility/move.hpp"

namespace etl {

namespace detail {
template <typename T>
inline constexpr auto move_if_noexcept_cond = is_nothrow_move_constructible_v<T>&& is_copy_constructible_v<T>;
} // namespace detail

/// \brief  Conditionally convert a value to an rvalue.
/// \details Same as etl::move unless the type's move constructor could throw
/// and the  type is copyable, in which case an lvalue-reference is returned
/// instead.
template <typename T>
[[nodiscard]] constexpr auto move_if_noexcept(T& x) noexcept
    -> conditional_t<detail::move_if_noexcept_cond<T>, T const&, T&&>
{
    return etl::move(x);
}

} // namespace etl

#endif // TETL_UTILITY_MOVE_IF_NOEXCEPT_HPP
