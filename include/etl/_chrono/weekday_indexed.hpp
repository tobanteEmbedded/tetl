// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_WEEKDAY_INDEXED_HPP
#define TETL_CHRONO_WEEKDAY_INDEXED_HPP

#include "etl/_chrono/weekday.hpp"

namespace etl::chrono {

struct weekday_indexed {
    weekday_indexed() = default;
    constexpr weekday_indexed(chrono::weekday const& wd, uint32_t index) noexcept
        : wd_ { wd }, index_ { static_cast<uint8_t>(index) }
    {
    }

    [[nodiscard]] constexpr auto weekday() const noexcept -> chrono::weekday { return wd_; }
    [[nodiscard]] constexpr auto index() const noexcept -> uint32_t { return index_; }
    [[nodiscard]] constexpr auto ok() const noexcept -> bool
    {
        return weekday().ok() and ((index_ >= 1) and (index_ <= 5));
    }

private:
    chrono::weekday wd_;
    uint8_t index_;
};

[[nodiscard]] constexpr auto operator==(weekday_indexed const& lhs, weekday_indexed const& rhs) noexcept -> bool
{
    return lhs.weekday() == rhs.weekday() && lhs.index() == rhs.index();
}

} // namespace etl::chrono

#endif // TETL_CHRONO_WEEKDAY_INDEXED_HPP
