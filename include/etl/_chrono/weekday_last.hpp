// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_WEEKDAY_LAST_HPP
#define TETL_CHRONO_WEEKDAY_LAST_HPP

#include "etl/_chrono/weekday.hpp"

namespace etl::chrono {

struct weekday_last {
    constexpr explicit weekday_last(chrono::weekday const& wd) noexcept : _wd{wd} { }

    [[nodiscard]] constexpr auto weekday() const noexcept -> chrono::weekday { return _wd; }

    [[nodiscard]] constexpr auto ok() const noexcept -> bool { return _wd.ok(); }

private:
    chrono::weekday _wd;
};

} // namespace etl::chrono

#endif // TETL_CHRONO_WEEKDAY_LAST_HPP
