// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_MONTH_DAY_HPP
#define TETL_CHRONO_MONTH_DAY_HPP

#include "etl/_array/array.hpp"
#include "etl/_chrono/day.hpp"
#include "etl/_chrono/month.hpp"

namespace etl::chrono {

struct month_day {
    month_day() = default;
    constexpr month_day(chrono::month const& m, chrono::day const& d) noexcept : m_ { m }, d_ { d } { }

    [[nodiscard]] constexpr auto month() const noexcept -> chrono::month { return m_; }
    [[nodiscard]] constexpr auto day() const noexcept -> chrono::day { return d_; }
    [[nodiscard]] constexpr auto ok() const noexcept -> bool
    {
        constexpr auto maxDaysInMonth = array<uint8_t, 12> { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
        if (not month().ok()) { return false; }
        if (static_cast<uint32_t>(day()) < 1) { return false; }
        return static_cast<uint32_t>(day()) <= maxDaysInMonth[uint32_t { month() }];
    }

private:
    chrono::month m_;
    chrono::day d_;
};

} // namespace etl::chrono

#endif // TETL_CHRONO_MONTH_DAY_HPP
