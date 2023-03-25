/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CHRONO_YEAR_MONTH_WEEKDAY_LAST_HPP
#define TETL_CHRONO_YEAR_MONTH_WEEKDAY_LAST_HPP

#include "etl/_chrono/local_t.hpp"
#include "etl/_chrono/month.hpp"
#include "etl/_chrono/system_clock.hpp"
#include "etl/_chrono/weekday.hpp"
#include "etl/_chrono/weekday_last.hpp"
#include "etl/_chrono/year.hpp"

namespace etl::chrono {

struct year_month_weekday_last {
    constexpr year_month_weekday_last(
        chrono::year const& y, chrono::month const& m, chrono::weekday_last const& wdl) noexcept;

    constexpr auto operator+=(months const& m) noexcept -> year_month_weekday_last&;
    constexpr auto operator-=(months const& m) noexcept -> year_month_weekday_last&;
    constexpr auto operator+=(years const& y) noexcept -> year_month_weekday_last&;
    constexpr auto operator-=(years const& y) noexcept -> year_month_weekday_last&;

    [[nodiscard]] constexpr auto year() const noexcept -> chrono::year;
    [[nodiscard]] constexpr auto month() const noexcept -> chrono::month;
    [[nodiscard]] constexpr auto weekday() const noexcept -> chrono::weekday;
    [[nodiscard]] constexpr auto weekday_last() const noexcept -> chrono::weekday_last;

    [[nodiscard]] constexpr operator sys_days() const noexcept;
    [[nodiscard]] constexpr explicit operator local_days() const noexcept;
    [[nodiscard]] constexpr auto ok() const noexcept -> bool;

public:
    chrono::year y_;
    chrono::month m_;
    chrono::weekday_last wdl_;
};

} // namespace etl::chrono

#endif // TETL_CHRONO_YEAR_MONTH_WEEKDAY_LAST_HPP
