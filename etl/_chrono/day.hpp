/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CHRONO_DAY_HPP
#define TETL_CHRONO_DAY_HPP

#include "etl/_chrono/duration.hpp"
#include "etl/_cstdint/uint_t.hpp"

namespace etl::chrono {

struct day {
    day() = default;

    constexpr explicit day(unsigned d) noexcept : count_ { static_cast<uint8_t>(d) } { }

    constexpr auto operator++() noexcept -> day& { return *this += days { 1 }; }

    constexpr auto operator++(int) noexcept -> day
    {
        auto tmp = *this;
        ++(*this);
        return tmp;
    }

    constexpr auto operator--() noexcept -> day& { return *this -= days { 1 }; }

    constexpr auto operator--(int) noexcept -> day
    {
        auto tmp = *this;
        --(*this);
        return tmp;
    }

    constexpr auto operator+=(days const& d) noexcept -> day&
    {
        count_ += static_cast<uint8_t>(d.count());
        return *this;
    }

    constexpr auto operator-=(days const& d) noexcept -> day&
    {
        count_ -= static_cast<uint8_t>(d.count());
        return *this;
    }

    constexpr explicit operator unsigned() const noexcept { return count_; }

    constexpr auto ok() const noexcept -> bool { return (count_ > 0U) && (count_ < 32U); }

private:
    uint8_t count_;
};

[[nodiscard]] constexpr auto operator==(day const& lhs, day const& rhs) noexcept -> bool
{
    return static_cast<unsigned>(lhs) == static_cast<unsigned>(rhs);
}

[[nodiscard]] constexpr auto operator+(day const& d, days const& ds) noexcept -> day
{
    return day(static_cast<unsigned>(d) + static_cast<unsigned>(ds.count()));
}

[[nodiscard]] constexpr auto operator+(days const& ds, day const& d) noexcept -> day
{
    return day(static_cast<unsigned>(d) + static_cast<unsigned>(ds.count()));
}

[[nodiscard]] constexpr auto operator-(day const& d, days const& ds) noexcept -> day
{
    return day(static_cast<unsigned>(d) - static_cast<unsigned>(ds.count()));
}

[[nodiscard]] constexpr auto operator-(day const& x, day const& y) noexcept -> days
{
    return days(int(unsigned(x)) - int(unsigned(y)));
}

} // namespace etl::chrono

#endif // TETL_CHRONO_DAY_HPP