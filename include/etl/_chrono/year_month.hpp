/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

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

    constexpr auto operator+=(months const& dm) noexcept -> year_month&;
    constexpr auto operator-=(months const& dm) noexcept -> year_month&;

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

} // namespace etl::chrono

#endif // TETL_CHRONO_YEAR_MONTH_HPP
