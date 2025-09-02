// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_WEEKDAY_HPP
#define TETL_CHRONO_WEEKDAY_HPP

#include <etl/_chrono/duration.hpp>
#include <etl/_chrono/last_spec.hpp>
#include <etl/_chrono/local_t.hpp>
#include <etl/_chrono/system_clock.hpp>
#include <etl/_cstdint/uint_t.hpp>

namespace etl::chrono {

struct weekday_indexed;
struct weekday_last;

/// \ingroup chrono
struct weekday {
    weekday() = default;

    constexpr explicit weekday(unsigned wd) noexcept
        : _wd{static_cast<etl::uint8_t>(wd == 7 ? 0 : wd)}
    {
    }

    constexpr weekday(sys_days const& dp) noexcept
        : _wd{weekday_from_days(dp.time_since_epoch().count())}
    {
    }

    constexpr explicit weekday(local_days const& dp) noexcept
        : _wd{weekday_from_days(dp.time_since_epoch().count())}
    {
    }

    constexpr auto operator++() noexcept -> weekday& { return *this += etl::chrono::days{1}; }

    constexpr auto operator++(int) noexcept -> weekday { return *this += etl::chrono::days{1}; }

    constexpr auto operator--() noexcept -> weekday& { return *this -= etl::chrono::days{1}; }

    constexpr auto operator--(int) noexcept -> weekday { return *this -= etl::chrono::days{1}; }

    constexpr auto operator+=(days const& d) noexcept -> weekday&
    {
        _wd += d.count();
        _wd %= 7;
        return *this;
    }

    constexpr auto operator-=(days const& d) noexcept -> weekday&
    {
        _wd -= d.count();
        _wd %= 7;
        return *this;
    }

    [[nodiscard]] constexpr auto c_encoding() const noexcept -> unsigned { return _wd; }

    [[nodiscard]] constexpr auto iso_encoding() const noexcept -> unsigned { return _wd == 0U ? 7U : _wd; }

    [[nodiscard]] constexpr auto ok() const noexcept -> bool { return _wd < 7U; }

    // Defined in weekday_indexed
    [[nodiscard]] constexpr auto operator[](unsigned index) const noexcept -> weekday_indexed;

    // Defined in weekday_last
    [[nodiscard]] constexpr auto operator[](etl::chrono::last_spec /*tag*/) const noexcept -> weekday_last;

    friend constexpr auto operator==(weekday const& lhs, weekday const& rhs) noexcept -> bool
    {
        return lhs.c_encoding() == rhs.c_encoding();
    }

private:
    [[nodiscard]] static constexpr auto weekday_from_days(int tp) noexcept -> etl::uint8_t
    {
        return static_cast<etl::uint8_t>(tp >= -4 ? (tp + 4) % 7 : ((tp + 5) % 7) + 6);
    }

    etl::uint8_t _wd;
};

[[nodiscard]] constexpr auto operator+(weekday const& lhs, days const& rhs) noexcept -> weekday
{
    return weekday{static_cast<unsigned>((static_cast<int32_t>(lhs.c_encoding()) + rhs.count()) % 7)};
}

[[nodiscard]] constexpr auto operator+(days const& lhs, weekday const& rhs) noexcept -> weekday { return rhs + lhs; }

[[nodiscard]] constexpr auto operator-(weekday const& lhs, days const& rhs) noexcept -> weekday
{
    return weekday{static_cast<unsigned>((static_cast<int32_t>(lhs.c_encoding()) - rhs.count()) % 7)};
}

[[nodiscard]] constexpr auto operator-(weekday const& lhs, weekday const& rhs) noexcept -> days
{
    auto const count = static_cast<int_least32_t>(lhs.c_encoding() - rhs.c_encoding());
    return count >= 0 ? days{count} : days{count + 7};
}

inline constexpr auto Sunday    = etl::chrono::weekday{0}; // NOLINT(readability-identifier-naming)
inline constexpr auto Monday    = etl::chrono::weekday{1}; // NOLINT(readability-identifier-naming)
inline constexpr auto Tuesday   = etl::chrono::weekday{2}; // NOLINT(readability-identifier-naming)
inline constexpr auto Wednesday = etl::chrono::weekday{3}; // NOLINT(readability-identifier-naming)
inline constexpr auto Thursday  = etl::chrono::weekday{4}; // NOLINT(readability-identifier-naming)
inline constexpr auto Friday    = etl::chrono::weekday{5}; // NOLINT(readability-identifier-naming)
inline constexpr auto Saturday  = etl::chrono::weekday{6}; // NOLINT(readability-identifier-naming)

} // namespace etl::chrono

#endif // TETL_CHRONO_WEEKDAY_HPP
