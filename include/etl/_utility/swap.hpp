// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_UTILITY_SWAP_HPP
#define TETL_UTILITY_SWAP_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_type_traits/is_move_assignable.hpp"
#include "etl/_type_traits/is_move_constructible.hpp"
#include "etl/_type_traits/is_nothrow_move_assignable.hpp"
#include "etl/_type_traits/is_nothrow_move_constructible.hpp"
#include "etl/_type_traits/is_swappable.hpp"
#include "etl/_type_traits/remove_reference.hpp"
#include "etl/_utility/move.hpp"

namespace etl {

/// \brief Exchanges the given values. Swaps the values a and b. This overload
/// does not participate in overload resolution unless
/// etl::is_move_constructible_v<T> && etl::is_move_assignable_v<T> is true.
///
/// \details https://en.cppreference.com/w/cpp/algorithm/swap
template <typename T>
    requires(is_move_constructible_v<T> and is_move_assignable_v<T>)
constexpr auto swap(T& a, T& b) noexcept(is_nothrow_move_constructible_v<T> && is_nothrow_move_assignable_v<T>) -> void
{
    T temp(move(a));
    a = move(b);
    b = move(temp);
}

template <typename T, size_t N>
    requires(is_swappable_v<T>)
constexpr auto swap(T (&a)[N], T (&b)[N]) noexcept(is_nothrow_swappable<T>::value) -> void
{
    for (size_t i = 0; i < N; ++i) { swap(a[i], b[i]); }
}

} // namespace etl

#endif // TETL_UTILITY_SWAP_HPP
