// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_MONTH_WEEKDAY_LAST_HPP
#define TETL_CHRONO_MONTH_WEEKDAY_LAST_HPP

#include <etl/_chrono/month.hpp>
#include <etl/_chrono/weekday_last.hpp>

namespace etl::chrono {

/// \ingroup chrono
struct month_weekday_last {
    constexpr month_weekday_last(chrono::month const& m, chrono::weekday_last const& wdl) noexcept
        : _m{m}
        , _wdl{wdl}
    {
    }

    [[nodiscard]] constexpr auto ok() const noexcept -> bool { return month().ok() and weekday_last().ok(); }

    [[nodiscard]] constexpr auto month() const noexcept -> chrono::month { return _m; }
    [[nodiscard]] constexpr auto weekday_last() const noexcept -> chrono::weekday_last { return _wdl; }

    friend constexpr auto operator==(month_weekday_last const& lhs, month_weekday_last const& rhs) noexcept -> bool
    {
        return lhs.month() == rhs.month() and lhs.weekday_last() == rhs.weekday_last();
    }

private:
    chrono::month _m;
    chrono::weekday_last _wdl;
};

[[nodiscard]] constexpr auto operator/(month const& m, weekday_last const& wdl) noexcept -> month_weekday_last
{
    return {m, wdl};
}

[[nodiscard]] constexpr auto operator/(int m, weekday_last const& wdl) noexcept -> month_weekday_last
{
    return {month(static_cast<unsigned>(m)), wdl};
}

[[nodiscard]] constexpr auto operator/(weekday_last const& wdl, month const& m) noexcept -> month_weekday_last
{
    return {m, wdl};
}

[[nodiscard]] constexpr auto operator/(weekday_last const& wdl, int m) noexcept -> month_weekday_last
{
    return {month(static_cast<unsigned>(m)), wdl};
}

} // namespace etl::chrono

#endif // TETL_CHRONO_MONTH_WEEKDAY_LAST_HPP
