// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_MONTH_DAY_LAST_HPP
#define TETL_CHRONO_MONTH_DAY_LAST_HPP

#include <etl/_chrono/month.hpp>

namespace etl::chrono {

/// \ingroup chrono
struct month_day_last {
    constexpr explicit month_day_last(chrono::month const& m) noexcept
        : _m{m}
    {
    }

    [[nodiscard]] constexpr auto month() const noexcept -> chrono::month { return _m; }

    [[nodiscard]] constexpr auto ok() const noexcept -> bool { return month().ok(); }

    friend constexpr auto operator==(month_day_last const& lhs, month_day_last const& rhs) noexcept -> bool
    {
        return lhs.month() == rhs.month();
    }

private:
    chrono::month _m;
};

[[nodiscard]] constexpr auto operator/(month const& m, last_spec /*tag*/) noexcept -> month_day_last
{
    return month_day_last{m};
}

[[nodiscard]] constexpr auto operator/(int m, last_spec /*tag*/) noexcept -> month_day_last
{
    return month_day_last{month(static_cast<etl::uint32_t>(m))};
}

[[nodiscard]] constexpr auto operator/(last_spec /*tag*/, month const& m) noexcept -> month_day_last
{
    return month_day_last{m};
}

[[nodiscard]] constexpr auto operator/(last_spec /*tag*/, int m) noexcept -> month_day_last
{
    return month_day_last{month(static_cast<etl::uint32_t>(m))};
}

} // namespace etl::chrono

#endif // TETL_CHRONO_MONTH_DAY_LAST_HPP
