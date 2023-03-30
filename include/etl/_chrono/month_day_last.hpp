// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_MONTH_DAY_LAST_HPP
#define TETL_CHRONO_MONTH_DAY_LAST_HPP

#include "etl/_chrono/month.hpp"

namespace etl::chrono {

struct month_day_last {
    constexpr explicit month_day_last(chrono::month const& m) noexcept : m_ { m } { }

    [[nodiscard]] constexpr auto month() const noexcept -> chrono::month { return m_; }
    [[nodiscard]] constexpr auto ok() const noexcept -> bool { return month().ok(); }

private:
    chrono::month m_;
};

} // namespace etl::chrono

#endif // TETL_CHRONO_MONTH_DAY_LAST_HPP
