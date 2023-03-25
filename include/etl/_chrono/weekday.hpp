/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CHRONO_WEEKDAY_HPP
#define TETL_CHRONO_WEEKDAY_HPP

#include "etl/_chrono/duration.hpp"
#include "etl/_chrono/local_t.hpp"
#include "etl/_chrono/system_clock.hpp"
#include "etl/_cstdint/uint_t.hpp"

namespace etl::chrono {

struct weekday {
    weekday() = default;
    constexpr explicit weekday(uint32_t wd) noexcept : wd_ { static_cast<etl::uint8_t>(wd == 7 ? 0 : wd) } { }
    constexpr weekday(sys_days const& dp) noexcept
        : wd_ { static_cast<uint8_t>(weekday_from_days(dp.time_since_epoch().count())) }
    {
    }
    constexpr explicit weekday(local_days const& dp) noexcept
        : wd_ { static_cast<uint8_t>(weekday_from_days(dp.time_since_epoch().count())) }
    {
    }

    constexpr auto operator++() noexcept -> weekday& { return *this += etl::chrono::days { 1 }; }
    constexpr auto operator++(int) noexcept -> weekday { return *this += etl::chrono::days { 1 }; }
    constexpr auto operator--() noexcept -> weekday& { return *this -= etl::chrono::days { 1 }; }
    constexpr auto operator--(int) noexcept -> weekday { return *this -= etl::chrono::days { 1 }; }

    constexpr auto operator+=(days const& d) noexcept -> weekday&
    {
        wd_ += d.count();
        wd_ %= 7;
        return *this;
    }
    constexpr auto operator-=(days const& d) noexcept -> weekday&
    {
        wd_ -= d.count();
        wd_ %= 7;
        return *this;
    }

    [[nodiscard]] constexpr auto c_encoding() const noexcept -> uint32_t { return wd_; }
    [[nodiscard]] constexpr auto iso_encoding() const noexcept -> uint32_t { return wd_ == 0u ? 7u : wd_; }
    [[nodiscard]] constexpr auto ok() const noexcept -> bool { return wd_ < 7U; }

    // [[nodiscard]] constexpr auto operator[](uint32_t index) const noexcept -> weekday_indexed { }
    // [[nodiscard]] constexpr auto operator[](last_spec) const noexcept -> weekday_last { }

private:
    [[nodiscard]] static constexpr auto weekday_from_days(int tp) noexcept -> uint32_t
    {
        return static_cast<uint32_t>(tp >= -4 ? (tp + 4) % 7 : (tp + 5) % 7 + 6);
    }

    etl::uint8_t wd_;
};

[[nodiscard]] constexpr auto operator==(weekday const& lhs, weekday const& rhs) noexcept -> bool
{
    return lhs.c_encoding() == rhs.c_encoding();
}

[[nodiscard]] constexpr auto operator!=(weekday const& lhs, weekday const& rhs) noexcept -> bool
{
    return lhs.c_encoding() != rhs.c_encoding();
}

[[nodiscard]] constexpr auto operator+(weekday const& lhs, days const& rhs) noexcept -> weekday
{
    return weekday { static_cast<uint32_t>((static_cast<int32_t>(lhs.c_encoding()) + rhs.count()) % 7) };
}

[[nodiscard]] constexpr auto operator+(days const& lhs, weekday const& rhs) noexcept -> weekday { return rhs + lhs; }

[[nodiscard]] constexpr auto operator-(weekday const& lhs, days const& rhs) noexcept -> weekday
{
    return weekday { static_cast<uint32_t>((static_cast<int32_t>(lhs.c_encoding()) - rhs.count()) % 7) };
}

inline constexpr auto Sunday    = etl::chrono::weekday { 0 }; // NOLINT(readability-identifier-naming)
inline constexpr auto Monday    = etl::chrono::weekday { 1 }; // NOLINT(readability-identifier-naming)
inline constexpr auto Tuesday   = etl::chrono::weekday { 2 }; // NOLINT(readability-identifier-naming)
inline constexpr auto Wednesday = etl::chrono::weekday { 3 }; // NOLINT(readability-identifier-naming)
inline constexpr auto Thursday  = etl::chrono::weekday { 4 }; // NOLINT(readability-identifier-naming)
inline constexpr auto Friday    = etl::chrono::weekday { 5 }; // NOLINT(readability-identifier-naming)
inline constexpr auto Saturday  = etl::chrono::weekday { 6 }; // NOLINT(readability-identifier-naming)

} // namespace etl::chrono

#endif // TETL_CHRONO_WEEKDAY_HPP
