// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_MONTH_HPP
#define TETL_CHRONO_MONTH_HPP

#include <etl/_chrono/duration.hpp>
#include <etl/_contracts/check.hpp>
#include <etl/_limits/numeric_limits.hpp>

namespace etl::chrono {

/// The class month represents a month in a year.
///
/// Its normal range is [1, 12], but it may hold any number in [​0​, 255].
/// Twelve named constants are predefined in the etl::chrono namespace
/// for the twelve months of the year.
///
/// - https://en.cppreference.com/w/cpp/chrono/month
///
/// \ingroup chrono
struct month {
    month() = default;

    constexpr explicit month(unsigned m) noexcept
        : _count{static_cast<unsigned char>(m)}
    {
        TETL_PRECONDITION(m < etl::numeric_limits<unsigned char>::max());
    }

    [[nodiscard]] constexpr auto ok() const noexcept -> bool
    {
        return (_count > 0U) and (_count <= 12U);
    }

    constexpr explicit operator unsigned() const noexcept
    {
        return _count;
    }

    constexpr auto operator++() noexcept -> month&;
    constexpr auto operator++(int) noexcept -> month;
    constexpr auto operator--() noexcept -> month&;
    constexpr auto operator--(int) noexcept -> month;

    constexpr auto operator+=(months const& m) noexcept -> month&;
    constexpr auto operator-=(months const& m) noexcept -> month&;

private:
    unsigned char _count;
};

[[nodiscard]] constexpr auto operator==(month lhs, month rhs) noexcept -> bool
{
    return static_cast<unsigned>(lhs) == static_cast<unsigned>(rhs);
}

[[nodiscard]] constexpr auto operator<(month lhs, month rhs) noexcept -> bool
{
    return static_cast<unsigned>(lhs) < static_cast<unsigned>(rhs);
}

[[nodiscard]] constexpr auto operator<=(month lhs, month rhs) noexcept -> bool
{
    return static_cast<unsigned>(lhs) <= static_cast<unsigned>(rhs);
}

[[nodiscard]] constexpr auto operator>(month lhs, month rhs) noexcept -> bool
{
    return static_cast<unsigned>(lhs) > static_cast<unsigned>(rhs);
}

[[nodiscard]] constexpr auto operator>=(month lhs, month rhs) noexcept -> bool
{
    return static_cast<unsigned>(lhs) >= static_cast<unsigned>(rhs);
}

[[nodiscard]] constexpr auto operator+(month const& m, months const& ms) noexcept -> month
{
    auto const mo  = static_cast<long long>(static_cast<unsigned>(m)) + (ms.count() - 1);
    auto const div = (mo >= 0 ? mo : mo - 11) / 12;
    return month{static_cast<unsigned int>(mo - (div * 12) + 1)};
}

[[nodiscard]] constexpr auto operator+(months const& ms, month const& m) noexcept -> month
{
    return m + ms;
}

[[nodiscard]] constexpr auto operator-(month const& m, months const& ms) noexcept -> month
{
    return m + -ms;
}

[[nodiscard]] constexpr auto operator-(month const& m1, month const& m2) noexcept -> months
{
    auto const delta = static_cast<unsigned>(m1) - static_cast<unsigned>(m2);
    return months{static_cast<etl::int_least32_t>(delta <= 11 ? delta : delta + 12)};
}

constexpr auto month::operator++() noexcept -> month&
{
    *this = *this + months{1};
    return *this;
}

constexpr auto month::operator++(int) noexcept -> month
{
    auto tmp = *this;
    ++(*this);
    return tmp;
}

constexpr auto month::operator--() noexcept -> month&
{
    *this = *this - months{1};
    return *this;
}

constexpr auto month::operator--(int) noexcept -> month
{
    auto tmp = *this;
    --(*this);
    return tmp;
}

constexpr auto month::operator+=(months const& m) noexcept -> month&
{
    *this = *this + m;
    return *this;
}

constexpr auto month::operator-=(months const& m) noexcept -> month&
{
    *this = *this - m;
    return *this;
}

inline constexpr auto January   = etl::chrono::month{1};
inline constexpr auto February  = etl::chrono::month{2};
inline constexpr auto March     = etl::chrono::month{3};
inline constexpr auto April     = etl::chrono::month{4};
inline constexpr auto May       = etl::chrono::month{5};
inline constexpr auto June      = etl::chrono::month{6};
inline constexpr auto July      = etl::chrono::month{7};
inline constexpr auto August    = etl::chrono::month{8};
inline constexpr auto September = etl::chrono::month{9};
inline constexpr auto October   = etl::chrono::month{10};
inline constexpr auto November  = etl::chrono::month{11};
inline constexpr auto December  = etl::chrono::month{12};

} // namespace etl::chrono

#endif // TETL_CHRONO_MONTH_HPP
