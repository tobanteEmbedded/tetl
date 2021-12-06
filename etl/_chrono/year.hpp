/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CHRONO_MONTH_HPP
#define TETL_CHRONO_MONTH_HPP

#include "etl/_chrono/duration.hpp"
#include "etl/_cstdint/uint_t.hpp"

namespace etl::chrono {

struct year {
    year() = default;

    constexpr explicit year(int y) noexcept : count_ { static_cast<short>(y) }
    {
    }

    constexpr year& operator++() noexcept
    {
        ++count_;
        return *this;
    }

    constexpr auto operator++(int) noexcept -> year
    {
        return year { count_++ };
    }

    constexpr auto operator--() noexcept -> year&
    {
        --count_;
        return *this;
    }

    constexpr auto operator--(int) noexcept -> year
    {
        return year { count_-- };
    }

    constexpr auto operator+=(years const& count_s) noexcept -> year&
    {

        count_ += static_cast<short>(count_s.count());
        return *this;
    }

    constexpr auto operator-=(years const& count_s) noexcept -> year&
    {
        count_ -= static_cast<short>(count_s.count());
        return *this;
    }

    [[nodiscard]] constexpr year operator+() const noexcept { return *this; }

    [[nodiscard]] constexpr year operator-() const noexcept
    {
        return year { -count_ };
    }

    [[nodiscard]] constexpr bool is_leap() const noexcept
    {
        return (count_ % 4 == 0) && (count_ % 100 != 0 || count_ % 400 == 0);
    }

    [[nodiscard]] constexpr explicit operator int() const noexcept
    {
        return count_;
    }

    [[nodiscard]] constexpr bool ok() const noexcept
    {
        return min_ <= count_ && count_ <= max_;
    }

    [[nodiscard]] static constexpr auto min() noexcept -> year
    {
        return year { min_ };
    }

    [[nodiscard]] static constexpr auto max() noexcept -> year
    {
        return year { max_ };
    }

private:
    short count_;
    static constexpr int min_ = -32767;
    static constexpr int max_ = 32767;
};

[[nodiscard]] constexpr auto operator==(
    year const& lhs, year const& rhs) noexcept -> bool
{
    return static_cast<int>(lhs) == static_cast<int>(rhs);
}

[[nodiscard]] constexpr auto operator+(
    year const& lhs, years const& rhs) noexcept -> year
{
    return year { static_cast<int>(lhs) + rhs.count() };
}

[[nodiscard]] constexpr auto operator+(
    years const& lhs, year const& rhs) noexcept -> year
{
    return rhs + lhs;
}

[[nodiscard]] constexpr auto operator-(
    year const& lhs, years const& rhs) noexcept -> year
{
    return lhs + -rhs;
}

[[nodiscard]] constexpr auto operator-(
    year const& lhs, year const& rhs) noexcept -> years
{
    return years { static_cast<int>(lhs) - static_cast<int>(rhs) };
}

} // namespace etl::chrono

#endif // TETL_CHRONO_MONTH_HPP
