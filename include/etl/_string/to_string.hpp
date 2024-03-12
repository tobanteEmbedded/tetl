// SPDX-License-Identifier: BSL-1.0
#ifndef TETL_STRING_TO_STRING_HPP
#define TETL_STRING_TO_STRING_HPP

#include "etl/_cassert/macro.hpp"
#include "etl/_string/static_string.hpp"
#include "etl/_strings/conversion.hpp"

namespace etl {

namespace detail {
template <size_t Capacity, typename Int>
constexpr auto to_string_impl(Int val) -> static_string<Capacity>
{
    char buffer[Capacity]{};
    auto* first    = etl::begin(buffer);
    auto const res = detail::integer_to_string<Int>(val, first, 10, Capacity);
    if (res.error == detail::integer_to_string_error::none) {
        return static_string<Capacity>{first, res.end};
    }
    return {};
}
} // namespace detail

/// \brief Converts a numeric value to etl::static_string.
template <size_t Capacity>
[[nodiscard]] constexpr auto to_string(int value) noexcept -> static_string<Capacity>
{
    return detail::to_string_impl<Capacity, int>(value);
}

/// \brief Converts a numeric value to etl::static_string.
template <size_t Capacity>
[[nodiscard]] constexpr auto to_string(long value) noexcept -> static_string<Capacity>
{
    return detail::to_string_impl<Capacity, long>(value);
}

/// \brief Converts a numeric value to etl::static_string.
template <size_t Capacity>
[[nodiscard]] constexpr auto to_string(long long value) noexcept -> static_string<Capacity>
{
    return detail::to_string_impl<Capacity, long long>(value);
}

/// \brief Converts a numeric value to etl::static_string.
template <size_t Capacity>
[[nodiscard]] constexpr auto to_string(unsigned value) noexcept -> static_string<Capacity>
{
    return detail::to_string_impl<Capacity, unsigned>(value);
}

/// \brief Converts a numeric value to etl::static_string.
template <size_t Capacity>
[[nodiscard]] constexpr auto to_string(unsigned long value) noexcept -> static_string<Capacity>
{
    return detail::to_string_impl<Capacity, unsigned long>(value);
}

/// \brief Converts a numeric value to etl::static_string.
template <size_t Capacity>
[[nodiscard]] constexpr auto to_string(unsigned long long value) noexcept -> static_string<Capacity>
{
    return detail::to_string_impl<Capacity, unsigned long long>(value);
}

/// \brief Converts a numeric value to etl::static_string.
template <size_t Capacity>
[[nodiscard]] constexpr auto to_string(float value) noexcept -> static_string<Capacity>
{
    TETL_ASSERT(false);
    ignore_unused(value);
    return {};
}

/// \brief Converts a numeric value to etl::static_string.
template <size_t Capacity>
[[nodiscard]] constexpr auto to_string(double value) noexcept -> static_string<Capacity>
{
    TETL_ASSERT(false);
    ignore_unused(value);
    return {};
}

/// \brief Converts a numeric value to etl::static_string.
template <size_t Capacity>
[[nodiscard]] constexpr auto to_string(long double value) noexcept -> static_string<Capacity>
{
    TETL_ASSERT(false);
    ignore_unused(value);
    return {};
}

} // namespace etl

#endif // TETL_STRING_TO_STRING_HPP
