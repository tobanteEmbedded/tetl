// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_YEAR_MONTH_HPP
#define TETL_CHRONO_YEAR_MONTH_HPP

#include "etl/_chrono/month.hpp"

namespace etl::chrono {

struct year_month {
    year_month() = default;
    constexpr year_month(chrono::year const& y, chrono::month const& m) noexcept : y_ { y }, m_ { m } { }

    [[nodiscard]] constexpr auto year() const noexcept -> chrono::year { return y_; }
    [[nodiscard]] constexpr auto month() const noexcept -> chrono::month { return m_; }

    [[nodiscard]] constexpr auto ok() const noexcept -> bool { return year().ok() and month().ok(); }

    constexpr auto operator+=(months const& dm) noexcept -> year_month&
    {
        m_ += dm;
        return *this;
    }

    constexpr auto operator-=(months const& dm) noexcept -> year_month&
    {
        m_ -= dm;
        return *this;
    }

    constexpr auto operator+=(years const& dy) noexcept -> year_month&
    {
        y_ += dy;
        return *this;
    }

    constexpr auto operator-=(years const& dy) noexcept -> year_month&
    {
        y_ -= dy;
        return *this;
    }

private:
    chrono::year y_;
    chrono::month m_;
};

[[nodiscard]] constexpr auto operator==(year_month const& lhs, year_month const& rhs) noexcept -> bool
{
    return lhs.year() == rhs.year() && lhs.month() == rhs.month();
}

[[nodiscard]] constexpr auto operator+(chrono::year_month const& ym, chrono::years const& dy) noexcept
    -> chrono::year_month
{
    return chrono::year_month { ym.year() + dy, ym.month() };
}

[[nodiscard]] constexpr auto operator+(chrono::years const& dy, chrono::year_month const& ym) noexcept
    -> chrono::year_month
{
    return chrono::year_month { ym.year() + dy, ym.month() };
}

// [[nodiscard]] constexpr auto operator+(chrono::year_month const& ym, chrono::months const& dm) noexcept
//     -> chrono::year_month
// {
// }

// [[nodiscard]] constexpr auto operator+(chrono::months const& dm, chrono::year_month const& ym) noexcept
//     -> chrono::year_month
// {
// }

// [[nodiscard]] constexpr auto operator-(chrono::year_month const& ym, chrono::years const& dy) noexcept
//     -> chrono::year_month
// {
// }

// [[nodiscard]] constexpr auto operator-(chrono::year_month const& ym, chrono::months const& dm) noexcept
//     -> chrono::year_month
// {
// }

// [[nodiscard]] constexpr auto operator-(chrono::year_month const& ym1, chrono::year_month const& ym2) noexcept
//     -> chrono::months
// {
// }

} // namespace etl::chrono

#endif // TETL_CHRONO_YEAR_MONTH_HPP
