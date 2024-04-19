// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_WEEKDAY_INDEXED_HPP
#define TETL_CHRONO_WEEKDAY_INDEXED_HPP

#include <etl/_chrono/weekday.hpp>

namespace etl::chrono {

/// \ingroup chrono
struct weekday_indexed {
    weekday_indexed() = default;

    constexpr weekday_indexed(etl::chrono::weekday const& wd, unsigned index) noexcept
        : _wd{wd}
        , _index{static_cast<etl::uint8_t>(index)}
    {
    }

    [[nodiscard]] constexpr auto weekday() const noexcept -> etl::chrono::weekday { return _wd; }

    [[nodiscard]] constexpr auto index() const noexcept -> unsigned { return _index; }

    [[nodiscard]] constexpr auto ok() const noexcept -> bool
    {
        return weekday().ok() and ((_index >= 1) and (_index <= 5));
    }

    friend constexpr auto operator==(weekday_indexed const& lhs, weekday_indexed const& rhs) noexcept -> bool
    {
        return lhs.weekday() == rhs.weekday() and lhs.index() == rhs.index();
    }

private:
    etl::chrono::weekday _wd;
    etl::uint8_t _index;
};

constexpr auto weekday::operator[](unsigned index) const noexcept -> weekday_indexed { return {*this, index}; }

} // namespace etl::chrono

#endif // TETL_CHRONO_WEEKDAY_INDEXED_HPP
