// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_UTILITY_EXCHANGE_HPP
#define TETL_UTILITY_EXCHANGE_HPP

#include <etl/_type_traits/is_nothrow_move_assignable.hpp>
#include <etl/_type_traits/is_nothrow_move_constructible.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/move.hpp>

namespace etl {

/// \brief Replaces the value of obj with new_value and returns the old value of obj.
/// \returns The old value of obj.
template <typename T, typename U = T>
[[nodiscard]] constexpr auto
exchange(T& obj, U&& newValue) noexcept(etl::is_nothrow_move_constructible_v<T> and etl::is_nothrow_assignable_v<T&, U>)
    -> T
{
    T oldValue = etl::move(obj);
    obj        = etl::forward<U>(newValue);
    return oldValue;
}

} // namespace etl

#endif // TETL_UTILITY_EXCHANGE_HPP
