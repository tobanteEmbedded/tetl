// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_UTILITY_SWAP_HPP
#define TETL_UTILITY_SWAP_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_type_traits/is_move_assignable.hpp>
#include <etl/_type_traits/is_move_constructible.hpp>
#include <etl/_type_traits/is_nothrow_move_assignable.hpp>
#include <etl/_type_traits/is_nothrow_move_constructible.hpp>
#include <etl/_type_traits/is_swappable.hpp>
#include <etl/_type_traits/remove_reference.hpp>
#include <etl/_utility/move.hpp>

namespace etl {

/// \brief Exchanges the given values. Swaps the values a and b. This overload
/// does not participate in overload resolution unless
/// etl::is_move_constructible_v<T> && etl::is_move_assignable_v<T> is true.
///
/// \details https://en.cppreference.com/w/cpp/algorithm/swap
template <typename T>
    requires(etl::is_move_constructible_v<T> and etl::is_move_assignable_v<T>)
constexpr auto
swap(T& a, T& b) noexcept(etl::is_nothrow_move_constructible_v<T> and etl::is_nothrow_move_assignable_v<T>) -> void
{
    T temp(etl::move(a));
    a = etl::move(b);
    b = etl::move(temp);
}

template <typename T, etl::size_t N>
    requires(etl::is_swappable_v<T>)
constexpr auto swap(T (&a)[N], T (&b)[N]) noexcept(etl::is_nothrow_swappable<T>::value) -> void
{
    for (etl::size_t i = 0; i < N; ++i) {
        swap(a[i], b[i]);
    }
}

} // namespace etl

#endif // TETL_UTILITY_SWAP_HPP
