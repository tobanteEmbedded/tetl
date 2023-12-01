// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_LITERALS_HPP
#define TETL_CHRONO_LITERALS_HPP

#include "etl/_chrono/day.hpp"
#include "etl/_chrono/duration.hpp"

namespace etl::inline literals::inline chrono_literals {

/// \brief Forms a etl::chrono::day literal representing a day of the month in
/// the calendar.
constexpr auto operator""_d(unsigned long long d) noexcept -> etl::chrono::day
{
    return etl::chrono::day {static_cast<uint32_t>(d)};
}

/// \brief Forms a etl::chrono::duration literal representing hours.
/// Integer literal, returns exactly etl::chrono::hours(hrs).
constexpr auto operator""_h(unsigned long long h) -> etl::chrono::hours
{
    return etl::chrono::hours(static_cast<etl::chrono::hours::rep>(h));
}

/// \brief Forms a etl::chrono::duration literal representing hours.
/// Floating-point literal, returns a floating-point duration equivalent
/// to etl::chrono::hours.
constexpr auto operator""_h(long double h) -> etl::chrono::duration<long double, ratio<3600, 1>>
{
    return etl::chrono::duration<long double, etl::ratio<3600, 1>>(h);
}

/// \brief Forms a etl::chrono::duration literal representing minutes.
/// Integer literal, returns exactly etl::chrono::minutes(mins).
constexpr auto operator""_min(unsigned long long m) -> etl::chrono::minutes
{
    return etl::chrono::minutes(static_cast<etl::chrono::minutes::rep>(m));
}

/// \brief Forms a etl::chrono::duration literal representing minutes.
/// Floating-point literal, returns a floating-point duration equivalent
/// to etl::chrono::minutes.
constexpr auto operator""_min(long double m) -> etl::chrono::duration<long double, etl::ratio<60, 1>>
{
    return etl::chrono::duration<long double, ratio<60, 1>>(m);
}

/// \brief Forms a etl::chrono::duration literal representing seconds.
/// Integer literal, returns exactly etl::chrono::seconds(mins).
constexpr auto operator""_s(unsigned long long m) -> etl::chrono::seconds
{
    return etl::chrono::seconds(static_cast<etl::chrono::seconds::rep>(m));
}

/// \brief Forms a etl::chrono::duration literal representing seconds.
/// Floating-point literal, returns a floating-point duration equivalent
/// to etl::chrono::seconds.
constexpr auto operator""_s(long double m) -> etl::chrono::duration<long double>
{
    return etl::chrono::duration<long double>(m);
}

/// \brief Forms a etl::chrono::duration literal representing
/// milliseconds. Integer literal, returns exactly
/// etl::chrono::milliseconds(mins).
constexpr auto operator""_ms(unsigned long long m) -> etl::chrono::milliseconds
{
    return etl::chrono::milliseconds(static_cast<etl::chrono::milliseconds::rep>(m));
}

/// \brief Forms a etl::chrono::duration literal representing
/// milliseconds. Floating-point literal, returns a floating-point
/// duration equivalent to etl::chrono::milliseconds.
constexpr auto operator""_ms(long double m) -> etl::chrono::duration<long double, etl::milli>
{
    return etl::chrono::duration<long double, etl::milli>(m);
}

/// \brief Forms a etl::chrono::duration literal representing
/// microseconds. Integer literal, returns exactly
/// etl::chrono::microseconds(mins).
constexpr auto operator""_us(unsigned long long m) -> etl::chrono::microseconds
{
    return etl::chrono::microseconds(static_cast<etl::chrono::microseconds::rep>(m));
}

/// \brief Forms a etl::chrono::duration literal representing
/// microseconds. Floating-point literal, returns a floating-point
/// duration equivalent to etl::chrono::microseconds.
constexpr auto operator""_us(long double m) -> etl::chrono::duration<long double, etl::micro>
{
    return etl::chrono::duration<long double, etl::micro>(m);
}

/// \brief Forms a etl::chrono::duration literal representing
/// nanoseconds. Integer literal, returns exactly
/// etl::chrono::nanoseconds(mins).
constexpr auto operator""_ns(unsigned long long m) -> etl::chrono::nanoseconds
{
    return etl::chrono::nanoseconds(static_cast<etl::chrono::nanoseconds::rep>(m));
}

/// \brief Forms a etl::chrono::duration literal representing
/// nanoseconds. Floating-point literal, returns a floating-point
/// duration equivalent to etl::chrono::nanoseconds.
constexpr auto operator""_ns(long double m) -> etl::chrono::duration<long double, etl::nano>
{
    return etl::chrono::duration<long double, etl::nano>(m);
}

} // namespace etl::inline literals::inline chrono_literals

namespace et_l::chrono {
using namespace etl::literals::chrono_literals;
} // namespace et_l::chrono

#endif // TETL_CHRONO_LITERALS_HPP
