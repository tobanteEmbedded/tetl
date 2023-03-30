// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_MONTH_WEEKDAY_LAST_HPP
#define TETL_CHRONO_MONTH_WEEKDAY_LAST_HPP

#include "etl/_chrono/month.hpp"
#include "etl/_chrono/weekday_last.hpp"

namespace etl::chrono {

struct month_weekday_last {
    constexpr month_weekday_last(chrono::month const& m, chrono::weekday_last const& wdl) noexcept
        : m_ { m }, wdl_ { wdl }
    {
    }

    [[nodiscard]] constexpr auto month() const noexcept -> chrono::month { return m_; }
    [[nodiscard]] constexpr auto weekday_last() const noexcept -> chrono::weekday_last { return wdl_; }
    [[nodiscard]] constexpr auto ok() const noexcept -> bool { return month().ok() and weekday_last().ok(); }

private:
    chrono::month m_;
    chrono::weekday_last wdl_;
};

} // namespace etl::chrono

#endif // TETL_CHRONO_MONTH_WEEKDAY_LAST_HPP
