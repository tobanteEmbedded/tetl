// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_YEAR_HPP
#define TETL_CHRONO_YEAR_HPP

#include <etl/_chrono/duration.hpp>
#include <etl/_cstdint/int_t.hpp>
#include <etl/_cstdint/uint_t.hpp>
#include <etl/_limits/numeric_limits.hpp>

namespace etl::chrono {

struct year {
    year() = default;

    constexpr explicit year(int y) noexcept
        : _count{static_cast<int16_t>(y)}
    {
    }

    constexpr auto operator++() noexcept -> year&
    {
        ++_count;
        return *this;
    }

    constexpr auto operator++(int) noexcept -> year { return year{_count++}; }

    constexpr auto operator--() noexcept -> year&
    {
        --_count;
        return *this;
    }

    constexpr auto operator--(int) noexcept -> year { return year{_count--}; }

    constexpr auto operator+=(years const& countS) noexcept -> year&
    {

        _count = static_cast<int16_t>(_count + countS.count());
        return *this;
    }

    constexpr auto operator-=(years const& countS) noexcept -> year&
    {
        _count = static_cast<int16_t>(_count - countS.count());
        return *this;
    }

    [[nodiscard]] constexpr auto operator+() const noexcept -> year { return *this; }

    [[nodiscard]] constexpr auto operator-() const noexcept -> year { return year{-_count}; }

    [[nodiscard]] constexpr auto is_leap() const noexcept -> bool
    {
        return (_count % 4 == 0) and (_count % 100 != 0 or _count % 400 == 0);
    }

    [[nodiscard]] constexpr explicit operator int() const noexcept { return _count; }

    [[nodiscard]] constexpr auto ok() const noexcept -> bool { return _count != numeric_limits<int16_t>::min(); }

    [[nodiscard]] static constexpr auto min() noexcept -> year { return year{-32767}; }

    [[nodiscard]] static constexpr auto max() noexcept -> year { return year{32767}; }

    friend constexpr auto operator==(year lhs, year rhs) noexcept -> bool
    {
        return static_cast<int>(lhs) == static_cast<int>(rhs);
    }

    friend constexpr auto operator<(year lhs, year rhs) noexcept -> bool
    {
        return static_cast<int>(lhs) < static_cast<int>(rhs);
    }

    friend constexpr auto operator<=(year lhs, year rhs) noexcept -> bool
    {
        return static_cast<int>(lhs) <= static_cast<int>(rhs);
    }

    friend constexpr auto operator>(year lhs, year rhs) noexcept -> bool
    {
        return static_cast<int>(lhs) > static_cast<int>(rhs);
    }

    friend constexpr auto operator>=(year lhs, year rhs) noexcept -> bool
    {
        return static_cast<int>(lhs) >= static_cast<int>(rhs);
    }

private:
    int16_t _count;
};

[[nodiscard]] constexpr auto operator+(year const& lhs, years const& rhs) noexcept -> year
{
    return year{static_cast<int>(static_cast<int>(lhs) + rhs.count())};
}

[[nodiscard]] constexpr auto operator+(years const& lhs, year const& rhs) noexcept -> year { return rhs + lhs; }

[[nodiscard]] constexpr auto operator-(year const& lhs, years const& rhs) noexcept -> year { return lhs + -rhs; }

[[nodiscard]] constexpr auto operator-(year const& lhs, year const& rhs) noexcept -> years
{
    return years{static_cast<int>(lhs) - static_cast<int>(rhs)};
}

} // namespace etl::chrono

// NOLINTNEXTLINE(modernize-concat-nested-namespaces)
namespace etl {
inline namespace literals {
inline namespace chrono_literals {

/// Forms a etl::chrono::year literal representing a year in the proleptic Gregorian calendar.
[[nodiscard]] constexpr auto operator""_y(unsigned long long y) noexcept -> etl::chrono::year
{
    return etl::chrono::year{static_cast<int>(y)};
}

} // namespace chrono_literals
} // namespace literals
} // namespace etl

namespace etl::chrono {
using namespace etl::literals::chrono_literals;
} // namespace etl::chrono

#endif // TETL_CHRONO_YEAR_HPP
