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
        chrono::year const& y, chrono::month const& m, chrono::weekday_indexed const& wdi) noexcept;
    constexpr year_month_weekday(sys_days const& dp) noexcept;
    constexpr explicit year_month_weekday(local_days const& dp) noexcept;

    constexpr year_month_weekday& operator+=(months const& m) noexcept;
    constexpr year_month_weekday& operator-=(months const& m) noexcept;
    constexpr year_month_weekday& operator+=(years const& y) noexcept;
    constexpr year_month_weekday& operator-=(years const& y) noexcept;

    constexpr chrono::year year() const noexcept;
    constexpr chrono::month month() const noexcept;
    constexpr chrono::weekday weekday() const noexcept;
    constexpr uint32_t index() const noexcept;
    constexpr chrono::weekday_indexed weekday_indexed() const noexcept;

    constexpr operator sys_days() const noexcept;
    constexpr explicit operator local_days() const noexcept;
    constexpr bool ok() const noexcept;

private:
    chrono::year y_;
    chrono::month m_;
    chrono::weekday_indexed wdi_;
};

} // namespace etl::chrono

#endif // TETL_CHRONO_YEAR_MONTH_WEEKDAY_HPP
