// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_DAY_HPP
#define TETL_CHRONO_DAY_HPP

#include <etl/_chrono/duration.hpp>
#include <etl/_cstdint/uint_t.hpp>

namespace etl::chrono {

/// The class day represents a day in a month.
///
/// Its normal range is [1, 31], but it may hold any number in [​0​, 255].
///
/// - https://en.cppreference.com/w/cpp/chrono/day
///
/// \ingroup chrono
struct day {
    day() = default;

    constexpr explicit day(etl::uint32_t d) noexcept
        : _count{static_cast<etl::uint8_t>(d)}
    {
    }

    constexpr auto operator++() noexcept -> day& { return *this += days{1}; }

    constexpr auto operator++(int) noexcept -> day
    {
        auto tmp = *this;
        ++(*this);
        return tmp;
    }

    constexpr auto operator--() noexcept -> day& { return *this -= days{1}; }

    constexpr auto operator--(int) noexcept -> day
    {
        auto tmp = *this;
        --(*this);
        return tmp;
    }

    constexpr auto operator+=(days const& d) noexcept -> day&
    {
        _count += static_cast<etl::uint8_t>(d.count());
        return *this;
    }

    constexpr auto operator-=(days const& d) noexcept -> day&
    {
        _count -= static_cast<etl::uint8_t>(d.count());
        return *this;
    }

    constexpr explicit operator etl::uint32_t() const noexcept { return _count; }

    [[nodiscard]] constexpr auto ok() const noexcept -> bool { return (_count > 0U) and (_count < 32U); }

    friend constexpr auto operator==(day lhs, day rhs) noexcept -> bool
    {
        return static_cast<etl::uint32_t>(lhs) == static_cast<etl::uint32_t>(rhs);
    }

    friend constexpr auto operator<(day lhs, day rhs) noexcept -> bool
    {
        return static_cast<etl::uint32_t>(lhs) < static_cast<etl::uint32_t>(rhs);
    }

    friend constexpr auto operator<=(day lhs, day rhs) noexcept -> bool
    {
        return static_cast<etl::uint32_t>(lhs) <= static_cast<etl::uint32_t>(rhs);
    }

    friend constexpr auto operator>(day lhs, day rhs) noexcept -> bool
    {
        return static_cast<etl::uint32_t>(lhs) > static_cast<etl::uint32_t>(rhs);
    }

    friend constexpr auto operator>=(day lhs, day rhs) noexcept -> bool
    {
        return static_cast<etl::uint32_t>(lhs) >= static_cast<etl::uint32_t>(rhs);
    }

private:
    etl::uint8_t _count;
};

[[nodiscard]] constexpr auto operator+(day const& d, days const& ds) noexcept -> day
{
    return day(static_cast<etl::uint32_t>(d) + static_cast<etl::uint32_t>(ds.count()));
}

[[nodiscard]] constexpr auto operator+(days const& ds, day const& d) noexcept -> day
{
    return day(static_cast<etl::uint32_t>(d) + static_cast<etl::uint32_t>(ds.count()));
}

[[nodiscard]] constexpr auto operator-(day const& d, days const& ds) noexcept -> day
{
    return day(static_cast<etl::uint32_t>(d) - static_cast<etl::uint32_t>(ds.count()));
}

[[nodiscard]] constexpr auto operator-(day const& x, day const& y) noexcept -> days
{
    return days(int(etl::uint32_t(x)) - int(etl::uint32_t(y)));
}

} // namespace etl::chrono

// NOLINTNEXTLINE(modernize-concat-nested-namespaces)
namespace etl {
inline namespace literals {
inline namespace chrono_literals {

/// \brief Forms a etl::chrono::day literal representing a day of the month in the calendar.
[[nodiscard]] constexpr auto operator""_d(unsigned long long d) noexcept -> etl::chrono::day
{
    return etl::chrono::day{static_cast<etl::uint32_t>(d)};
}

} // namespace chrono_literals
} // namespace literals
} // namespace etl

namespace etl::chrono {
using namespace etl::literals::chrono_literals;
} // namespace etl::chrono
#endif // TETL_CHRONO_DAY_HPP
