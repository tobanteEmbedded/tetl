// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_STRING_TO_STRING_HPP
#define TETL_STRING_TO_STRING_HPP

#include <etl/_string/static_string.hpp>
#include <etl/_strings/conversion.hpp>

namespace etl {

namespace detail {

template <etl::size_t Capacity, typename Int>
constexpr auto to_string(Int val) -> etl::static_string<Capacity>
{
    char buffer[Capacity]{};
    auto* first    = etl::begin(buffer);
    auto const res = etl::detail::integer_to_string<Int>(val, first, 10, Capacity);
    if (res.error == etl::detail::integer_to_string_error::none) {
        return etl::static_string<Capacity>{first, res.end};
    }
    return {};
}

} // namespace detail

/// \brief Converts a numeric value to etl::static_string.
template <etl::size_t Capacity>
[[nodiscard]] constexpr auto to_string(int value) noexcept -> etl::static_string<Capacity>
{
    return etl::detail::to_string<Capacity, int>(value);
}

/// \brief Converts a numeric value to etl::static_string.
template <etl::size_t Capacity>
[[nodiscard]] constexpr auto to_string(long value) noexcept -> etl::static_string<Capacity>
{
    return etl::detail::to_string<Capacity, long>(value);
}

/// \brief Converts a numeric value to etl::static_string.
template <etl::size_t Capacity>
[[nodiscard]] constexpr auto to_string(long long value) noexcept -> etl::static_string<Capacity>
{
    return etl::detail::to_string<Capacity, long long>(value);
}

/// \brief Converts a numeric value to etl::static_string.
template <etl::size_t Capacity>
[[nodiscard]] constexpr auto to_string(unsigned value) noexcept -> etl::static_string<Capacity>
{
    return etl::detail::to_string<Capacity, unsigned>(value);
}

/// \brief Converts a numeric value to etl::static_string.
template <etl::size_t Capacity>
[[nodiscard]] constexpr auto to_string(unsigned long value) noexcept -> etl::static_string<Capacity>
{
    return etl::detail::to_string<Capacity, unsigned long>(value);
}

/// \brief Converts a numeric value to etl::static_string.
template <etl::size_t Capacity>
[[nodiscard]] constexpr auto to_string(unsigned long long value) noexcept -> etl::static_string<Capacity>
{
    return etl::detail::to_string<Capacity, unsigned long long>(value);
}

} // namespace etl

#endif // TETL_STRING_TO_STRING_HPP
