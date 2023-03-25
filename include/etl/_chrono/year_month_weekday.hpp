/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CHRONO_YEAR_MONTH_WEEKDAY_HPP
#define TETL_CHRONO_YEAR_MONTH_WEEKDAY_HPP

#include "etl/_chrono/local_t.hpp"
#include "etl/_chrono/month.hpp"
#include "etl/_chrono/system_clock.hpp"
#include "etl/_chrono/weekday.hpp"
#include "etl/_chrono/weekday_indexed.hpp"
#include "etl/_chrono/year.hpp"

namespace etl::chrono {

struct year_month_weekday {
    year_month_weekday() = default;
    constexpr year_month_weekday(
        chrono::year const& y, chrono::month const& m, chrono::weekday_indexed const& wdi) noexcept
        : y_ { y }, m_ { m }, wdi_ { wdi }
    {
    }

    constexpr year_month_weekday(sys_days const& dp) noexcept;
    constexpr explicit year_month_weekday(local_days const& dp) noexcept;

    constexpr auto operator+=(months const& m) noexcept -> year_month_weekday&;
    constexpr auto operator-=(months const& m) noexcept -> year_month_weekday&;
    constexpr auto operator+=(years const& y) noexcept -> year_month_weekday&;
    constexpr auto operator-=(years const& y) noexcept -> year_month_weekday&;

    [[nodiscard]] constexpr auto year() const noexcept -> chrono::year { return y_; }
    [[nodiscard]] constexpr auto month() const noexcept -> chrono::month { return m_; }
    [[nodiscard]] constexpr auto weekday() const noexcept -> chrono::weekday { return wdi_.weekday(); }
    [[nodiscard]] constexpr auto index() const noexcept -> uint32_t { return wdi_.index(); }
    [[nodiscard]] constexpr auto weekday_indexed() const noexcept -> chrono::weekday_indexed { return wdi_; }

    [[nodiscard]] constexpr operator sys_days() const noexcept;
    [[nodiscard]] constexpr explicit operator local_days() const noexcept;
    [[nodiscard]] constexpr auto ok() const noexcept -> bool;

private:
    chrono::year y_;
    chrono::month m_;
    chrono::weekday_indexed wdi_;
};

[[nodiscard]] constexpr auto operator==(year_month_weekday const& lhs, year_month_weekday const& rhs) noexcept -> bool
{
    return lhs.year() == rhs.year() && lhs.month() == rhs.month() && lhs.weekday_indexed() == rhs.weekday_indexed();
}

[[nodiscard]] constexpr auto operator+(year_month_weekday const& lhs, months const& rhs) noexcept -> year_month_weekday
{
    auto const ym = year_month { lhs.year(), lhs.month() } + rhs;
    return { ym.year(), ym.month(), lhs.weekday_indexed() };
}

[[nodiscard]] constexpr auto operator+(months const& lhs, year_month_weekday const& rhs) noexcept -> year_month_weekday
{
    return rhs + lhs;
}

[[nodiscard]] constexpr auto operator-(year_month_weekday const& lhs, months const& rhs) noexcept -> year_month_weekday
{
    return lhs + -rhs;
}

[[nodiscard]] constexpr auto operator+(year_month_weekday const& lhs, years const& rhs) noexcept -> year_month_weekday
{
    return year_month_weekday { lhs.year() + rhs, lhs.month(), lhs.weekday_indexed() };
}

[[nodiscard]] constexpr auto operator+(years const& lhs, year_month_weekday const& rhs) noexcept -> year_month_weekday
{
    return rhs + lhs;
}

[[nodiscard]] constexpr auto operator-(year_month_weekday const& lhs, years const& rhs) noexcept -> year_month_weekday
{
    return lhs + -rhs;
}

} // namespace etl::chrono

#endif // TETL_CHRONO_YEAR_MONTH_WEEKDAY_HPP
