/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CHRONO_MONTH_HPP
#define TETL_CHRONO_MONTH_HPP

#include "etl/_chrono/duration.hpp"
#include "etl/_cstdint/uint_t.hpp"

namespace etl::chrono {

struct month {
    month() = default;

    constexpr explicit month(unsigned d) noexcept : count_ { static_cast<uint8_t>(d) } { }

    constexpr auto operator++() noexcept -> month&
    {
        add(months { 1 }.count());
        return *this;
    }

    constexpr auto operator++(int) noexcept -> month
    {
        auto tmp = *this;
        ++(*this);
        return tmp;
    }

    constexpr auto operator--() noexcept -> month&
    {
        sub(months { 1 }.count());
        return *this;
    }

    constexpr auto operator--(int) noexcept -> month
    {
        auto tmp = *this;
        --(*this);
        return tmp;
    }

    constexpr auto operator+=(months const& d) noexcept -> month&
    {
        add(d.count());
        return *this;
    }

    constexpr auto operator-=(months const& d) noexcept -> month&
    {
        sub(d.count());
        return *this;
    }

    constexpr explicit operator unsigned() const noexcept { return count_; }

    [[nodiscard]] constexpr auto ok() const noexcept -> bool { return (count_ > 0U) && (count_ < 12U); }

private:
    constexpr auto add(int count) noexcept -> void
    {
        count_ += static_cast<uint8_t>(count);
        count_ %= 12;
    }

    constexpr auto sub(int count) noexcept -> void
    {
        count_ -= static_cast<uint8_t>(count);
        count_ %= 12;
    }

    uint8_t count_;
};

[[nodiscard]] constexpr auto operator==(month const& lhs, month const& rhs) noexcept -> bool
{
    return static_cast<unsigned>(lhs) == static_cast<unsigned>(rhs);
}

inline constexpr auto January   = etl::chrono::month { 1 };
inline constexpr auto February  = etl::chrono::month { 2 };
inline constexpr auto March     = etl::chrono::month { 3 };
inline constexpr auto April     = etl::chrono::month { 4 };
inline constexpr auto May       = etl::chrono::month { 5 };
inline constexpr auto June      = etl::chrono::month { 6 };
inline constexpr auto July      = etl::chrono::month { 7 };
inline constexpr auto August    = etl::chrono::month { 8 };
inline constexpr auto September = etl::chrono::month { 9 };
inline constexpr auto October   = etl::chrono::month { 10 };
inline constexpr auto November  = etl::chrono::month { 11 };
inline constexpr auto December  = etl::chrono::month { 12 };

} // namespace etl::chrono

#endif // TETL_CHRONO_MONTH_HPP
