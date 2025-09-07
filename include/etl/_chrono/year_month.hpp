// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_CHRONO_YEAR_MONTH_HPP
#define TETL_CHRONO_YEAR_MONTH_HPP

#include <etl/_chrono/month.hpp>

namespace etl::chrono {

/// \ingroup chrono
struct year_month {
    year_month() = default;

    constexpr year_month(chrono::year const& y, chrono::month const& m) noexcept
        : _y{y}
        , _m{m}
    {
    }

    [[nodiscard]] constexpr auto ok() const noexcept -> bool
    {
        return year().ok() and month().ok();
    }
    [[nodiscard]] constexpr auto year() const noexcept -> chrono::year
    {
        return _y;
    }
    [[nodiscard]] constexpr auto month() const noexcept -> chrono::month
    {
        return _m;
    }

    constexpr auto operator+=(months const& dm) noexcept -> year_month&;
    constexpr auto operator-=(months const& dm) noexcept -> year_month&;
    constexpr auto operator+=(years const& dy) noexcept -> year_month&;
    constexpr auto operator-=(years const& dy) noexcept -> year_month&;

    friend constexpr auto operator==(year_month const& lhs, year_month const& rhs) noexcept -> bool
    {
        return lhs.year() == rhs.year() and lhs.month() == rhs.month();
    }

private:
    chrono::year _y;
    chrono::month _m;
};

[[nodiscard]] constexpr auto operator+(chrono::year_month const& ym, chrono::years const& dy) noexcept
    -> chrono::year_month
{
    return chrono::year_month{ym.year() + dy, ym.month()};
}

[[nodiscard]] constexpr auto operator+(chrono::years const& dy, chrono::year_month const& ym) noexcept
    -> chrono::year_month
{
    return chrono::year_month{ym.year() + dy, ym.month()};
}

[[nodiscard]] constexpr auto operator+(chrono::year_month const& ym, chrono::months const& dm) noexcept
    -> chrono::year_month
{
    return {ym.year(), ym.month() + dm};
}

[[nodiscard]] constexpr auto operator+(chrono::months const& dm, chrono::year_month const& ym) noexcept
    -> chrono::year_month
{
    return {ym.year(), ym.month() + dm};
}

[[nodiscard]] constexpr auto operator-(chrono::year_month const& ym, chrono::years const& dy) noexcept
    -> chrono::year_month
{
    return {ym.year() - dy, ym.month()};
}

[[nodiscard]] constexpr auto operator-(chrono::year_month const& ym, chrono::months const& dm) noexcept
    -> chrono::year_month
{
    return {ym.year(), ym.month() - dm};
}

// [[nodiscard]] constexpr auto operator-(chrono::year_month const& ym1, chrono::year_month const&
// ym2) noexcept
//     -> chrono::months
// {
// }

constexpr auto year_month::operator+=(months const& dm) noexcept -> year_month&
{
    *this = *this + dm;
    return *this;
}

constexpr auto year_month::operator-=(months const& dm) noexcept -> year_month&
{
    *this = *this - dm;
    return *this;
}

constexpr auto year_month::operator+=(years const& dy) noexcept -> year_month&
{
    *this = *this + dy;
    return *this;
}

constexpr auto year_month::operator-=(years const& dy) noexcept -> year_month&
{
    *this = *this - dy;
    return *this;
}

[[nodiscard]] constexpr auto operator/(year const& y, month const& m) noexcept -> year_month
{
    return year_month{y, m};
}

[[nodiscard]] constexpr auto operator/(year const& y, int m) noexcept -> year_month
{
    return year_month{y, month(static_cast<unsigned>(m))};
}

} // namespace etl::chrono

#endif // TETL_CHRONO_YEAR_MONTH_HPP
