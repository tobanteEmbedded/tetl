// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_MONTH_DAY_HPP
#define TETL_CHRONO_MONTH_DAY_HPP

#include <etl/_array/array.hpp>
#include <etl/_chrono/day.hpp>
#include <etl/_chrono/month.hpp>

namespace etl::chrono {

/// \ingroup chrono
struct month_day {
    month_day() = default;

    constexpr month_day(chrono::month const& m, chrono::day const& d) noexcept
        : _m{m}
        , _d{d}
    {
    }

    [[nodiscard]] constexpr auto month() const noexcept -> chrono::month { return _m; }

    [[nodiscard]] constexpr auto day() const noexcept -> chrono::day { return _d; }

    [[nodiscard]] constexpr auto ok() const noexcept -> bool
    {
        constexpr auto maxDaysInMonth = array<uint8_t, 12>{31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
        if (not month().ok()) {
            return false;
        }
        if (static_cast<uint32_t>(day()) < 1) {
            return false;
        }
        return static_cast<uint32_t>(day()) <= maxDaysInMonth[uint32_t{month()} - 1];
    }

    friend constexpr auto operator==(month_day const& lhs, month_day const& rhs) noexcept -> bool
    {
        return lhs.month() == rhs.month() and lhs.day() == rhs.day();
    }

private:
    chrono::month _m;
    chrono::day _d;
};

[[nodiscard]] constexpr auto operator/(month const& m, day const& d) noexcept -> month_day { return {m, d}; }
[[nodiscard]] constexpr auto operator/(month const& m, int d) noexcept -> month_day
{
    return {m, day(static_cast<etl::uint32_t>(d))};
}
[[nodiscard]] constexpr auto operator/(int m, day const& d) noexcept -> month_day
{
    return {month(static_cast<etl::uint32_t>(m)), d};
}
[[nodiscard]] constexpr auto operator/(day const& d, month const& m) noexcept -> month_day { return {m, d}; }
[[nodiscard]] constexpr auto operator/(day const& d, int m) noexcept -> month_day
{
    return {month(static_cast<etl::uint32_t>(m)), d};
}

} // namespace etl::chrono

#endif // TETL_CHRONO_MONTH_DAY_HPP
