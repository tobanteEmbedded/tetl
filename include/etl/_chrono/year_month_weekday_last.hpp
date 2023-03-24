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

    constexpr year_month_weekday_last& operator+=(months const& m) noexcept;
    constexpr year_month_weekday_last& operator-=(months const& m) noexcept;
    constexpr year_month_weekday_last& operator+=(years const& y) noexcept;
    constexpr year_month_weekday_last& operator-=(years const& y) noexcept;

    constexpr chrono::year year() const noexcept;
    constexpr chrono::month month() const noexcept;
    constexpr chrono::weekday weekday() const noexcept;
    constexpr chrono::weekday_last weekday_last() const noexcept;

    constexpr operator sys_days() const noexcept;
    constexpr explicit operator local_days() const noexcept;
    constexpr bool ok() const noexcept;

public:
    chrono::year y_;
    chrono::month m_;
    chrono::weekday_last wdl_;
};

} // namespace etl::chrono

#endif // TETL_CHRONO_YEAR_MONTH_WEEKDAY_LAST_HPP
