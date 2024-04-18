// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_WEEKDAY_LAST_HPP
#define TETL_CHRONO_WEEKDAY_LAST_HPP

#include <etl/_chrono/weekday.hpp>

namespace etl::chrono {

/// \ingroup chrono
struct weekday_last {
    constexpr explicit weekday_last(chrono::weekday const& wd) noexcept
        : _wd{wd}
    {
    }

    [[nodiscard]] constexpr auto weekday() const noexcept -> chrono::weekday { return _wd; }

    [[nodiscard]] constexpr auto ok() const noexcept -> bool { return _wd.ok(); }

    friend constexpr auto operator==(weekday_last lhs, weekday_last rhs) noexcept -> bool
    {
        return lhs.weekday() == rhs.weekday();
    }

private:
    chrono::weekday _wd;
};

constexpr auto weekday::operator[](etl::chrono::last_spec /*tag*/) const noexcept -> weekday_last
{
    return weekday_last{*this};
}

} // namespace etl::chrono

#endif // TETL_CHRONO_WEEKDAY_LAST_HPP
