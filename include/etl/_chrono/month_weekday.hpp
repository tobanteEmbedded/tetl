// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_MONTH_WEEKDAY_HPP
#define TETL_CHRONO_MONTH_WEEKDAY_HPP

#include <etl/_chrono/month.hpp>
#include <etl/_chrono/weekday_indexed.hpp>

namespace etl::chrono {

/// \ingroup chrono
struct month_weekday {
    constexpr month_weekday(chrono::month const& m, chrono::weekday_indexed const& wdi) noexcept
        : _m{m}
        , _wdi{wdi}
    {
    }

    [[nodiscard]] constexpr auto month() const noexcept -> chrono::month { return _m; }

    [[nodiscard]] constexpr auto weekday_indexed() const noexcept -> chrono::weekday_indexed { return _wdi; }

    [[nodiscard]] constexpr auto ok() const noexcept -> bool { return month().ok() and weekday_indexed().ok(); }

private:
    chrono::month _m;
    chrono::weekday_indexed _wdi;
};

} // namespace etl::chrono

#endif // TETL_CHRONO_MONTH_WEEKDAY_HPP
