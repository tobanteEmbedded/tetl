// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_YEAR_MONTH_DAY_HPP
#define TETL_CHRONO_YEAR_MONTH_DAY_HPP

#include <etl/_chrono/day.hpp>
#include <etl/_chrono/local_t.hpp>
#include <etl/_chrono/month.hpp>
#include <etl/_chrono/system_clock.hpp>
#include <etl/_chrono/year.hpp>
#include <etl/_chrono/year_month_day_last.hpp>
#include <etl/_limits/numeric_limits.hpp>

namespace etl::chrono {

/// \ingroup chrono
struct year_month_day {
private:
    // https://howardhinnant.github.io/date_algorithms.html#civil_from_days
    [[nodiscard]] static constexpr auto civil_from_days(int32_t z) noexcept -> year_month_day
    {
        static_assert(etl::numeric_limits<uint32_t>::digits >= 18, "Not yet ported to a 16 bit unsigned integer");
        static_assert(etl::numeric_limits<int32_t>::digits >= 20, "Not yet ported to a 16 bit signed integer");

        z += 719468;
        int32_t const era  = (z >= 0 ? z : z - 146096) / 146097;
        auto const doe     = static_cast<uint32_t>(z - era * 146097);
        uint32_t const yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        int32_t const y    = static_cast<int32_t>(yoe) + era * 400;
        uint32_t const doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        uint32_t const mp  = (5 * doy + 2) / 153;
        uint32_t const d   = doy - (153 * mp + 2) / 5 + 1;
        uint32_t const m   = mp < 10 ? mp + 3 : mp - 9;

        return {
            chrono::year{static_cast<int>(y) + static_cast<int>(m <= 2)},
            chrono::month{static_cast<unsigned>(m)},
            chrono::day{static_cast<unsigned>(d)},
        };
    }

    // https://howardhinnant.github.io/date_algorithms.html#days_from_civil
    [[nodiscard]] static constexpr auto days_from_civil(int32_t y, uint32_t m, uint32_t d) noexcept -> days
    {
        static_assert(etl::numeric_limits<uint32_t>::digits >= 18, "Not yet ported to a 16 bit unsigned integer");
        static_assert(etl::numeric_limits<int32_t>::digits >= 20, "Not yet ported to a 16 bit signed integer");

        y -= static_cast<int32_t>(m <= 2);
        int32_t const era  = (y >= 0 ? y : y - 399) / 400;
        auto const yoe     = static_cast<uint32_t>(y - era * 400);            // [0, 399]
        uint32_t const doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1; // [0, 365]
        uint32_t const doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;           // [0, 146096]
        return days{era * 146097 + static_cast<int32_t>(doe) - 719468};
    }

public:
    year_month_day() = default;

    constexpr year_month_day(chrono::year const& y, chrono::month const& m, chrono::day const& d) noexcept
        : _y{y}
        , _m{m}
        , _d{d}
    {
    }

    constexpr year_month_day(year_month_day_last const& ymdl) noexcept
        : _y{ymdl.year()}
        , _m{ymdl.month()}
        , _d{ymdl.day()}
    {
    }

    constexpr year_month_day(sys_days const& dp) noexcept
        : year_month_day{civil_from_days(dp.time_since_epoch().count())}
    {
    }

    constexpr explicit year_month_day(local_days const& dp) noexcept
        : year_month_day{civil_from_days(dp.time_since_epoch().count())}
    {
    }

    constexpr auto operator+=(months const& m) noexcept -> year_month_day&;
    constexpr auto operator-=(months const& m) noexcept -> year_month_day&;
    constexpr auto operator+=(years const& y) noexcept -> year_month_day&;
    constexpr auto operator-=(years const& y) noexcept -> year_month_day&;

    [[nodiscard]] constexpr auto year() const noexcept -> chrono::year { return _y; }

    [[nodiscard]] constexpr auto month() const noexcept -> chrono::month { return _m; }

    [[nodiscard]] constexpr auto day() const noexcept -> chrono::day { return _d; }

    [[nodiscard]] constexpr operator sys_days() const noexcept
    {
        return sys_days{days_from_civil(int{year()}, unsigned{month()}, unsigned{day()})};
    }

    [[nodiscard]] constexpr explicit operator local_days() const noexcept
    {
        return local_days{static_cast<sys_days>(*this).time_since_epoch()};
    }

    [[nodiscard]] constexpr auto ok() const noexcept -> bool
    {
        if (not year().ok() or not month().ok()) {
            return false;
        }
        return day() >= chrono::day{1} and day() <= detail::last_day_of_month(year(), month());
    }

private:
    chrono::year _y;
    chrono::month _m;
    chrono::day _d;
};

[[nodiscard]] constexpr auto operator==(year_month_day const& lhs, year_month_day const& rhs) noexcept -> bool
{
    return lhs.year() == rhs.year() and lhs.month() == rhs.month() and lhs.day() == rhs.day();
}

[[nodiscard]] constexpr auto operator+(chrono::year_month_day const& lhs, chrono::months const& rhs) noexcept
    -> chrono::year_month_day
{
    auto const ym = year_month{lhs.year(), lhs.month()} + rhs;
    return {ym.year(), ym.month(), lhs.day()};
}

[[nodiscard]] constexpr auto operator+(chrono::months const& lhs, chrono::year_month_day const& rhs) noexcept
    -> chrono::year_month_day
{
    return rhs + lhs;
}

[[nodiscard]] constexpr auto operator+(chrono::year_month_day const& lhs, chrono::years const& rhs) noexcept
    -> chrono::year_month_day
{
    return {lhs.year() + rhs, lhs.month(), lhs.day()};
}

[[nodiscard]] constexpr auto operator+(chrono::years const& lhs, chrono::year_month_day const& rhs) noexcept
    -> chrono::year_month_day
{
    return rhs + lhs;
}

[[nodiscard]] constexpr auto operator-(chrono::year_month_day const& lhs, chrono::months const& rhs) noexcept
    -> chrono::year_month_day
{
    return lhs + -rhs;
}

[[nodiscard]] constexpr auto operator-(chrono::year_month_day const& lhs, chrono::years const& rhs) noexcept
    -> chrono::year_month_day
{
    return lhs + -rhs;
}

constexpr auto year_month_day::operator+=(months const& m) noexcept -> year_month_day&
{
    *this = *this + m;
    return *this;
}

constexpr auto year_month_day::operator-=(months const& m) noexcept -> year_month_day&
{
    *this = *this - m;
    return *this;
}

constexpr auto year_month_day::operator+=(years const& y) noexcept -> year_month_day&
{
    *this = *this + y;
    return *this;
}

constexpr auto year_month_day::operator-=(years const& y) noexcept -> year_month_day&
{
    *this = *this - y;
    return *this;
}

[[nodiscard]] constexpr auto operator/(year_month const& ym, day const& d) noexcept -> year_month_day
{
    return {ym.year(), ym.month(), d};
}

[[nodiscard]] constexpr auto operator/(year_month const& ym, int d) noexcept -> year_month_day
{
    return {ym.year(), ym.month(), day(static_cast<unsigned>(d))};
}

[[nodiscard]] constexpr auto operator/(year const& y, month_day const& md) noexcept -> year_month_day
{
    return {y, md.month(), md.day()};
}

[[nodiscard]] constexpr auto operator/(int y, month_day const& md) noexcept -> year_month_day
{
    return {year{y}, md.month(), md.day()};
}

[[nodiscard]] constexpr auto operator/(month_day const& md, year const& y) noexcept -> year_month_day
{
    return {y, md.month(), md.day()};
}

[[nodiscard]] constexpr auto operator/(month_day const& md, int y) noexcept -> year_month_day
{
    return {year{y}, md.month(), md.day()};
}

} // namespace etl::chrono

#endif // TETL_CHRONO_YEAR_MONTH_DAY_HPP
