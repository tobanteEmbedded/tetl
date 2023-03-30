// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_MONTH_WEEKDAY_HPP
#define TETL_CHRONO_MONTH_WEEKDAY_HPP

#include "etl/_chrono/month.hpp"
#include "etl/_chrono/weekday_indexed.hpp"

namespace etl::chrono {

struct month_weekday {
    constexpr month_weekday(chrono::month const& m, chrono::weekday_indexed const& wdi) noexcept
        : m_ { m }, wdi_ { wdi }
    {
    }

    [[nodiscard]] constexpr auto month() const noexcept -> chrono::month { return m_; }
    [[nodiscard]] constexpr auto weekday_indexed() const noexcept -> chrono::weekday_indexed { return wdi_; }
    [[nodiscard]] constexpr auto ok() const noexcept -> bool { return month().ok() and weekday_indexed().ok(); }

private:
    chrono::month m_;
    chrono::weekday_indexed wdi_;
};

} // namespace etl::chrono

#endif // TETL_CHRONO_MONTH_WEEKDAY_HPP
