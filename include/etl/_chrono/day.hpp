// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_DAY_HPP
#define TETL_CHRONO_DAY_HPP

#include "etl/_chrono/duration.hpp"
#include "etl/_cstdint/uint_t.hpp"

namespace etl::chrono {

struct day {
    day() = default;

    constexpr explicit day(uint32_t d) noexcept : _count {static_cast<uint8_t>(d)} { }

    constexpr auto operator++() noexcept -> day& { return *this += days {1}; }

    constexpr auto operator++(int) noexcept -> day
    {
        auto tmp = *this;
        ++(*this);
        return tmp;
    }

    constexpr auto operator--() noexcept -> day& { return *this -= days {1}; }

    constexpr auto operator--(int) noexcept -> day
    {
        auto tmp = *this;
        --(*this);
        return tmp;
    }

    constexpr auto operator+=(days const& d) noexcept -> day&
    {
        _count += static_cast<uint8_t>(d.count());
        return *this;
    }

    constexpr auto operator-=(days const& d) noexcept -> day&
    {
        _count -= static_cast<uint8_t>(d.count());
        return *this;
    }

    constexpr explicit operator uint32_t() const noexcept { return _count; }

    [[nodiscard]] constexpr auto ok() const noexcept -> bool { return (_count > 0U) and (_count < 32U); }

private:
    uint8_t _count {};
};

[[nodiscard]] constexpr auto operator==(day lhs, day rhs) noexcept -> bool
{
    return static_cast<uint32_t>(lhs) == static_cast<uint32_t>(rhs);
}

[[nodiscard]] constexpr auto operator!=(day lhs, day rhs) noexcept -> bool
{
    return static_cast<uint32_t>(lhs) != static_cast<uint32_t>(rhs);
}

[[nodiscard]] constexpr auto operator<(day lhs, day rhs) noexcept -> bool
{
    return static_cast<uint32_t>(lhs) < static_cast<uint32_t>(rhs);
}

[[nodiscard]] constexpr auto operator<=(day lhs, day rhs) noexcept -> bool
{
    return static_cast<uint32_t>(lhs) <= static_cast<uint32_t>(rhs);
}

[[nodiscard]] constexpr auto operator>(day lhs, day rhs) noexcept -> bool
{
    return static_cast<uint32_t>(lhs) > static_cast<uint32_t>(rhs);
}

[[nodiscard]] constexpr auto operator>=(day lhs, day rhs) noexcept -> bool
{
    return static_cast<uint32_t>(lhs) >= static_cast<uint32_t>(rhs);
}

[[nodiscard]] constexpr auto operator+(day const& d, days const& ds) noexcept -> day
{
    return day(static_cast<uint32_t>(d) + static_cast<uint32_t>(ds.count()));
}

[[nodiscard]] constexpr auto operator+(days const& ds, day const& d) noexcept -> day
{
    return day(static_cast<uint32_t>(d) + static_cast<uint32_t>(ds.count()));
}

[[nodiscard]] constexpr auto operator-(day const& d, days const& ds) noexcept -> day
{
    return day(static_cast<uint32_t>(d) - static_cast<uint32_t>(ds.count()));
}

[[nodiscard]] constexpr auto operator-(day const& x, day const& y) noexcept -> days
{
    return days(int(uint32_t(x)) - int(uint32_t(y)));
}

} // namespace etl::chrono

#endif // TETL_CHRONO_DAY_HPP
