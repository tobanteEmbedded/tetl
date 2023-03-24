/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CHRONO_YEAR_MONTH_DAY_HPP
#define TETL_CHRONO_YEAR_MONTH_DAY_HPP

#include "etl/_chrono/day.hpp"
#include "etl/_chrono/local_t.hpp"
#include "etl/_chrono/month.hpp"
#include "etl/_chrono/system_clock.hpp"
#include "etl/_chrono/year.hpp"
#include "etl/_chrono/year_month_day_last.hpp"
#include "etl/_limits/numeric_limits.hpp"

namespace etl::chrono {

struct year_month_day {
    year_month_day() = default;
    constexpr year_month_day(chrono::year const& y, chrono::month const& m, chrono::day const& d) noexcept
        : y_ { y }, m_ { m }, d_ { d }
    {
    }
    constexpr year_month_day(year_month_day_last const& ymdl) noexcept
        : y_ { ymdl.year() }, m_ { ymdl.month() }, d_ { ymdl.day() }
    {
    }

    constexpr year_month_day(sys_days const& dp) noexcept
        : year_month_day { civil_from_days(dp.time_since_epoch().count()) }
    {
    }

    constexpr explicit year_month_day(local_days const& dp) noexcept
        : year_month_day { civil_from_days(dp.time_since_epoch().count()) }
    {
    }

    constexpr auto operator+=(months const& m) noexcept -> year_month_day&;
    constexpr auto operator-=(months const& m) noexcept -> year_month_day&;
    constexpr auto operator+=(years const& y) noexcept -> year_month_day&;
    constexpr auto operator-=(years const& y) noexcept -> year_month_day&;

    [[nodiscard]] constexpr auto year() const noexcept -> chrono::year { return y_; }
    [[nodiscard]] constexpr auto month() const noexcept -> chrono::month { return m_; }
    [[nodiscard]] constexpr auto day() const noexcept -> chrono::day { return d_; }

    [[nodiscard]] constexpr operator sys_days() const noexcept
    {
        return sys_days { days_from_civil(int { year() }, unsigned { month() }, unsigned { day() }) };
    }

    [[nodiscard]] constexpr explicit operator local_days() const noexcept
    {
        return local_days { static_cast<sys_days>(*this).time_since_epoch() };
    }

    [[nodiscard]] constexpr auto ok() const noexcept -> bool
    {
        if (not year().ok() or not month().ok()) { return false; }
        return day() >= chrono::day { 1 } and day() <= detail::last_day_of_month(year(), month());
    }

private:
    // https://howardhinnant.github.io/date_algorithms.html#civil_from_days
    template <typename Int>
    [[nodiscard]] static constexpr auto civil_from_days(Int z) noexcept -> year_month_day
    {
        static_assert(etl::numeric_limits<unsigned>::digits >= 18, "Not yet ported to a 16 bit unsigned integer");
        static_assert(etl::numeric_limits<Int>::digits >= 20, "Not yet ported to a 16 bit signed integer");

        z += 719468;
        Int const era      = (z >= 0 ? z : z - 146096) / 146097;
        unsigned const doe = static_cast<unsigned>(z - era * 146097);
        unsigned const yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        Int const y        = static_cast<Int>(yoe) + era * 400;
        unsigned const doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        unsigned const mp  = (5 * doy + 2) / 153;
        unsigned const d   = doy - (153 * mp + 2) / 5 + 1;
        unsigned const m   = mp < 10 ? mp + 3 : mp - 9;

        return {
            chrono::year { y + (m <= 2) },
            chrono::month { m },
            chrono::day { d },
        };
    }

    // https://howardhinnant.github.io/date_algorithms.html#days_from_civil
    template <typename Int>
    [[nodiscard]] static constexpr auto days_from_civil(Int y, unsigned m, unsigned d) noexcept -> days
    {
        static_assert(etl::numeric_limits<unsigned>::digits >= 18, "Not yet ported to a 16 bit unsigned integer");
        static_assert(etl::numeric_limits<Int>::digits >= 20, "Not yet ported to a 16 bit signed integer");
        y -= m <= 2;
        const Int era      = (y >= 0 ? y : y - 399) / 400;
        unsigned const yoe = static_cast<unsigned>(y - era * 400);            // [0, 399]
        unsigned const doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1; // [0, 365]
        unsigned const doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;           // [0, 146096]
        return days { era * 146097 + static_cast<Int>(doe) - 719468 };
    }

    chrono::year y_;
    chrono::month m_;
    chrono::day d_;
};

} // namespace etl::chrono

#endif // TETL_CHRONO_YEAR_MONTH_DAY_HPP
