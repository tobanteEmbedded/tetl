// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_YEAR_MONTH_DAY_LAST_HPP
#define TETL_CHRONO_YEAR_MONTH_DAY_LAST_HPP

#include <etl/_chrono/local_t.hpp>
#include <etl/_chrono/month_day_last.hpp>
#include <etl/_chrono/system_clock.hpp>
#include <etl/_chrono/year.hpp>

namespace etl::chrono {

namespace detail {

[[nodiscard]] constexpr auto last_day_of_month(chrono::year const& y, chrono::month const& m) -> chrono::day
{
    constexpr chrono::day lastDays[] = {
        chrono::day{31},
        chrono::day{28},
        chrono::day{31},
        chrono::day{30},
        chrono::day{31},
        chrono::day{30},
        chrono::day{31},
        chrono::day{31},
        chrono::day{30},
        chrono::day{31},
        chrono::day{30},
        chrono::day{31},
    };

    if (m == chrono::month{2} and y.is_leap()) {
        return chrono::day{29};
    }
    return lastDays[(static_cast<unsigned>(m) - 1) & static_cast<unsigned>(0xF)];
}

} // namespace detail

/// \ingroup chrono
struct year_month_day_last {
    constexpr year_month_day_last(chrono::year const& y, chrono::month_day_last const& mdl) noexcept
        : _y{y}
        , _mdl{mdl}
    {
    }

    constexpr auto operator+=(months const& m) noexcept -> year_month_day_last&;
    constexpr auto operator-=(months const& m) noexcept -> year_month_day_last&;
    constexpr auto operator+=(years const& y) noexcept -> year_month_day_last&;
    constexpr auto operator-=(years const& y) noexcept -> year_month_day_last&;

    [[nodiscard]] constexpr auto year() const noexcept -> chrono::year { return _y; }

    [[nodiscard]] constexpr auto month() const noexcept -> chrono::month { return _mdl.month(); }

    [[nodiscard]] constexpr auto month_day_last() const noexcept -> chrono::month_day_last { return _mdl; }

    [[nodiscard]] constexpr auto day() const noexcept -> chrono::day
    {
        return detail::last_day_of_month(year(), month());
    }

    [[nodiscard]] constexpr operator sys_days() const noexcept;
    [[nodiscard]] constexpr explicit operator local_days() const noexcept;

    [[nodiscard]] constexpr auto ok() const noexcept -> bool { return _y.ok() and _mdl.ok(); }

private:
    chrono::year _y;
    chrono::month_day_last _mdl;
};

[[nodiscard]] constexpr auto
operator+(chrono::year_month_day_last const& lhs, chrono::months const& rhs) noexcept -> chrono::year_month_day_last
{
    auto const ym = year_month{lhs.year(), lhs.month()} + rhs;
    return {ym.year(), month_day_last{ym.month()}};
}

[[nodiscard]] constexpr auto
operator+(chrono::months const& lhs, chrono::year_month_day_last const& rhs) noexcept -> chrono::year_month_day_last
{
    return rhs + lhs;
}

[[nodiscard]] constexpr auto
operator-(chrono::year_month_day_last const& lhs, chrono::months const& rhs) noexcept -> chrono::year_month_day_last
{
    return lhs + -rhs;
}

[[nodiscard]] constexpr auto
operator+(chrono::year_month_day_last const& lhs, chrono::years const& rhs) noexcept -> chrono::year_month_day_last
{
    return {lhs.year() + rhs, lhs.month_day_last()};
}

[[nodiscard]] constexpr auto
operator+(chrono::years const& lhs, chrono::year_month_day_last const& rhs) noexcept -> chrono::year_month_day_last
{
    return rhs + lhs;
}

[[nodiscard]] constexpr auto
operator-(chrono::year_month_day_last const& lhs, chrono::years const& rhs) noexcept -> chrono::year_month_day_last
{
    return lhs + -rhs;
}

constexpr auto year_month_day_last::operator+=(months const& m) noexcept -> year_month_day_last&
{
    *this = *this + m;
    return *this;
}

constexpr auto year_month_day_last::operator-=(months const& m) noexcept -> year_month_day_last&
{
    *this = *this - m;
    return *this;
}

constexpr auto year_month_day_last::operator+=(years const& y) noexcept -> year_month_day_last&
{
    *this = *this + y;
    return *this;
}

constexpr auto year_month_day_last::operator-=(years const& y) noexcept -> year_month_day_last&
{
    *this = *this - y;
    return *this;
}

} // namespace etl::chrono

#endif // TETL_CHRONO_YEAR_MONTH_DAY_LAST_HPP
