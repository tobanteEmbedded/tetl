// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_YEAR_MONTH_WEEKDAY_HPP
#define TETL_CHRONO_YEAR_MONTH_WEEKDAY_HPP

#include <etl/_chrono/local_t.hpp>
#include <etl/_chrono/month.hpp>
#include <etl/_chrono/system_clock.hpp>
#include <etl/_chrono/weekday.hpp>
#include <etl/_chrono/weekday_indexed.hpp>
#include <etl/_chrono/year.hpp>

namespace etl::chrono {

/// \ingroup chrono
struct year_month_weekday {
    year_month_weekday() = default;

    constexpr year_month_weekday(
        chrono::year const& y,
        chrono::month const& m,
        chrono::weekday_indexed const& wdi
    ) noexcept
        : _y{y}
        , _m{m}
        , _wdi{wdi}
    {
    }

    constexpr year_month_weekday(sys_days const& dp) noexcept;
    constexpr explicit year_month_weekday(local_days const& dp) noexcept;

    constexpr auto operator+=(months const& m) noexcept -> year_month_weekday&;
    constexpr auto operator-=(months const& m) noexcept -> year_month_weekday&;
    constexpr auto operator+=(years const& y) noexcept -> year_month_weekday&;
    constexpr auto operator-=(years const& y) noexcept -> year_month_weekday&;

    [[nodiscard]] constexpr auto year() const noexcept -> chrono::year { return _y; }
    [[nodiscard]] constexpr auto month() const noexcept -> chrono::month { return _m; }
    [[nodiscard]] constexpr auto weekday() const noexcept -> chrono::weekday { return _wdi.weekday(); }
    [[nodiscard]] constexpr auto index() const noexcept -> unsigned { return _wdi.index(); }
    [[nodiscard]] constexpr auto weekday_indexed() const noexcept -> chrono::weekday_indexed { return _wdi; }

    [[nodiscard]] constexpr auto ok() const noexcept -> bool
    {
        if (not _y.ok() or not _m.ok() or not _wdi.weekday().ok() or _wdi.index() < 1) {
            return false;
        }
        if (_wdi.index() <= 4) {
            return true;
        }
        auto firstOfMonth = chrono::weekday(static_cast<sys_days>(_y / _m / 1));
        auto d2 = _wdi.weekday() - firstOfMonth + days(static_cast<int_least32_t>(((_wdi.index() - 1) * 7) + 1));

        // NOLINTNEXTLINE(modernize-use-integer-sign-comparison)
        return static_cast<unsigned>(d2.count()) <= static_cast<unsigned>((_y / _m / last).day());
    }

    [[nodiscard]] constexpr operator sys_days() const noexcept;
    [[nodiscard]] constexpr explicit operator local_days() const noexcept;

private:
    chrono::year _y;
    chrono::month _m;
    chrono::weekday_indexed _wdi;
};

[[nodiscard]] constexpr auto operator==(year_month_weekday const& lhs, year_month_weekday const& rhs) noexcept -> bool
{
    return lhs.year() == rhs.year() and lhs.month() == rhs.month() and lhs.weekday_indexed() == rhs.weekday_indexed();
}

[[nodiscard]] constexpr auto operator+(year_month_weekday const& lhs, months const& rhs) noexcept -> year_month_weekday
{
    auto const ym = year_month{lhs.year(), lhs.month()} + rhs;
    return {ym.year(), ym.month(), lhs.weekday_indexed()};
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
    return year_month_weekday{lhs.year() + rhs, lhs.month(), lhs.weekday_indexed()};
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
