// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_STRING_TO_STRING_HPP
#define TETL_STRING_TO_STRING_HPP

#include <etl/_string/inplace_string.hpp>
#include <etl/_strings/from_integer.hpp>

namespace etl {

namespace detail {

template <etl::size_t Capacity, typename Int>
constexpr auto to_string(Int val) -> etl::inplace_string<Capacity>
{
    char buffer[Capacity]{};
    auto* first    = etl::begin(buffer);
    auto const res = etl::strings::from_integer<Int>(val, first, Capacity, 10);
    if (res.error == etl::strings::from_integer_error::none) {
        return etl::inplace_string<Capacity>{first, res.end};
    }
    return {};
}

} // namespace detail

/// \brief Converts a numeric value to etl::inplace_string.
template <etl::size_t Capacity>
[[nodiscard]] constexpr auto to_string(int value) noexcept -> etl::inplace_string<Capacity>
{
    return etl::detail::to_string<Capacity, int>(value);
}

/// \brief Converts a numeric value to etl::inplace_string.
template <etl::size_t Capacity>
[[nodiscard]] constexpr auto to_string(long value) noexcept -> etl::inplace_string<Capacity>
{
    return etl::detail::to_string<Capacity, long>(value);
}

/// \brief Converts a numeric value to etl::inplace_string.
template <etl::size_t Capacity>
[[nodiscard]] constexpr auto to_string(long long value) noexcept -> etl::inplace_string<Capacity>
{
    return etl::detail::to_string<Capacity, long long>(value);
}

/// \brief Converts a numeric value to etl::inplace_string.
template <etl::size_t Capacity>
[[nodiscard]] constexpr auto to_string(unsigned value) noexcept -> etl::inplace_string<Capacity>
{
    return etl::detail::to_string<Capacity, unsigned>(value);
}

/// \brief Converts a numeric value to etl::inplace_string.
template <etl::size_t Capacity>
[[nodiscard]] constexpr auto to_string(unsigned long value) noexcept -> etl::inplace_string<Capacity>
{
    return etl::detail::to_string<Capacity, unsigned long>(value);
}

/// \brief Converts a numeric value to etl::inplace_string.
template <etl::size_t Capacity>
[[nodiscard]] constexpr auto to_string(unsigned long long value) noexcept -> etl::inplace_string<Capacity>
{
    return etl::detail::to_string<Capacity, unsigned long long>(value);
}

} // namespace etl

#endif // TETL_STRING_TO_STRING_HPP
