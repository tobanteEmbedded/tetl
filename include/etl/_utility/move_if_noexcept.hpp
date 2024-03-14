

// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_UTILITY_MOVE_IF_NOEXCEPT_HPP
#define TETL_UTILITY_MOVE_IF_NOEXCEPT_HPP

#include <etl/_type_traits/conditional.hpp>
#include <etl/_type_traits/is_copy_constructible.hpp>
#include <etl/_type_traits/is_nothrow_move_constructible.hpp>
#include <etl/_utility/move.hpp>

namespace etl {

/// \brief  Conditionally convert a value to an rvalue.
/// \details Same as etl::move unless the type's move constructor could throw
/// and the  type is copyable, in which case an lvalue-reference is returned
/// instead.
template <typename T>
[[nodiscard]] constexpr auto move_if_noexcept(T& x) noexcept
    -> etl::conditional_t<!etl::is_nothrow_move_constructible_v<T> and etl::is_copy_constructible_v<T>, T const&, T&&>
{
    return TETL_MOVE(x);
}

} // namespace etl

#endif // TETL_UTILITY_MOVE_IF_NOEXCEPT_HPP
