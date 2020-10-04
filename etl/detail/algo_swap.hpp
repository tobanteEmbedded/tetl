#pragma once

#include "etl/type_traits.hpp"

namespace etl
{
namespace detail
{
template <typename T>
constexpr auto internal_move(T&& t) noexcept -> etl::remove_reference_t<T>&&
{
    return static_cast<etl::remove_reference_t<T>&&>(t);
}
}  // namespace detail

/**
 * @brief Exchanges the given values. Swaps the values a and b. This overload
 * does not participate in overload resolution unless
 * etl::is_move_constructible_v<T> && etl::is_move_assignable_v<T> is true.
 *
 * https://en.cppreference.com/w/cpp/algorithm/swap
 *
 * @todo Fix noexcept specifier.
 */
template <typename T>
constexpr auto swap(T& a, T& b) noexcept -> void
{
    T temp(etl::detail::internal_move(a));
    a = etl::detail::internal_move(b);
    b = etl::detail::internal_move(temp);
}

}  // namespace etl