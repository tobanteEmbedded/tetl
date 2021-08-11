// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_CHRONO_HPP
#define TETL_CHRONO_HPP

// Somehow the abs macro gets included in avr-gcc builds. Not sure where it's
// coming from.
#ifdef abs
#undef abs
#endif

#include "etl/version.hpp"

#include "etl/_chrono/abs.hpp"
#include "etl/_chrono/ceil.hpp"
#include "etl/_chrono/duration.hpp"
#include "etl/_chrono/duration_cast.hpp"
#include "etl/_chrono/duration_values.hpp"
#include "etl/_chrono/floor.hpp"
#include "etl/_chrono/round.hpp"
#include "etl/_chrono/time_point.hpp"
#include "etl/_chrono/treat_as_floating_point.hpp"

#include "etl/_concepts/requires.hpp"
#include "etl/_limits/numeric_limits.hpp"
#include "etl/_numeric/lcm.hpp"
#include "etl/_type_traits/common_type.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_arithmetic.hpp"
#include "etl/_type_traits/is_convertible.hpp"

namespace etl::chrono {

template <typename ToDuration, typename Clock, typename Duration,
    TETL_REQUIRES_(detail::is_duration<ToDuration>::value)>
[[nodiscard]] constexpr auto time_point_cast(
    time_point<Clock, Duration> const& tp) -> ToDuration
{
    using time_point_t = time_point<Clock, ToDuration>;
    return time_point_t(duration_cast<ToDuration>(tp.time_since_epoch()));
}

template <typename To, typename Clock, typename Duration,
    TETL_REQUIRES_(detail::is_duration<To>::value)>
[[nodiscard]] constexpr auto floor(time_point<Clock, Duration> const& tp)
    -> time_point<Clock, To>
{
    return time_point<Clock, To> { floor<To>(tp.time_since_epoch()) };
}

template <typename To, typename Clock, typename Duration,
    TETL_REQUIRES_(detail::is_duration<To>::value)>
[[nodiscard]] constexpr auto ceil(time_point<Clock, Duration> const& tp)
    -> time_point<Clock, To>
{
    return time_point<Clock, To> { ceil<To>(tp.time_since_epoch()) };
}

template <typename To, typename Clock, typename Duration,
    TETL_REQUIRES_(detail::is_duration<To>::value)>
[[nodiscard]] constexpr auto round(time_point<Clock, Duration> const& tp)
    -> time_point<Clock, To>
{
    return time_point<Clock, To> { round<To>(tp.time_since_epoch()) };
}

} // namespace etl::chrono

namespace etl {
/// \brief Exposes the type named type, which is the common type of two
/// etl::chrono::durations, whose period is the greatest common divisor of
/// Period1 and Period2.
/// \details The period of the resulting duration can be computed by forming a
/// ratio of the greatest common divisor of Period1::num and Period2::num and
/// the least common multiple of Period1::den and Period2::den.
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
struct common_type<chrono::duration<Rep1, Period1>,
    chrono::duration<Rep2, Period2>> {
private:
    static constexpr auto num = gcd(Period1::num, Period2::num);
    static constexpr auto den = lcm(Period1::den, Period2::den);

public:
    using type = chrono::duration<common_type_t<Rep1, Rep2>, ratio<num, den>>;
};

/// \brief Exposes the type named type, which is the common type of two
/// chrono::time_points.
template <typename Clock, typename Duration1, typename Duration2>
struct common_type<chrono::time_point<Clock, Duration1>,
    chrono::time_point<Clock, Duration2>> {
    using type = chrono::time_point<Clock, common_type_t<Duration1, Duration2>>;
};

inline namespace literals {
inline namespace chrono_literals {
/// \brief Forms a etl::chrono::duration literal representing hours.
/// Integer literal, returns exactly etl::chrono::hours(hrs).
constexpr auto operator""_h(unsigned long long h) -> etl::chrono::hours
{
    return etl::chrono::hours(static_cast<etl::chrono::hours::rep>(h));
}

/// \brief Forms a etl::chrono::duration literal representing hours.
/// Floating-point literal, returns a floating-point duration equivalent
/// to etl::chrono::hours.
constexpr auto operator""_h(long double h)
    -> etl::chrono::duration<long double, ratio<3600, 1>>
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
constexpr auto operator""_min(long double m)
    -> etl::chrono::duration<long double, etl::ratio<60, 1>>
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
    return etl::chrono::milliseconds(
        static_cast<etl::chrono::milliseconds::rep>(m));
}

/// \brief Forms a etl::chrono::duration literal representing
/// milliseconds. Floating-point literal, returns a floating-point
/// duration equivalent to etl::chrono::milliseconds.
constexpr auto operator""_ms(long double m)
    -> etl::chrono::duration<long double, etl::milli>
{
    return etl::chrono::duration<long double, etl::milli>(m);
}

/// \brief Forms a etl::chrono::duration literal representing
/// microseconds. Integer literal, returns exactly
/// etl::chrono::microseconds(mins).
constexpr auto operator""_us(unsigned long long m) -> etl::chrono::microseconds
{
    return etl::chrono::microseconds(
        static_cast<etl::chrono::microseconds::rep>(m));
}

/// \brief Forms a etl::chrono::duration literal representing
/// microseconds. Floating-point literal, returns a floating-point
/// duration equivalent to etl::chrono::microseconds.
constexpr auto operator""_us(long double m)
    -> etl::chrono::duration<long double, etl::micro>
{
    return etl::chrono::duration<long double, etl::micro>(m);
}

/// \brief Forms a etl::chrono::duration literal representing
/// nanoseconds. Integer literal, returns exactly
/// etl::chrono::nanoseconds(mins).
constexpr auto operator""_ns(unsigned long long m) -> etl::chrono::nanoseconds
{
    return etl::chrono::nanoseconds(
        static_cast<etl::chrono::nanoseconds::rep>(m));
}

/// \brief Forms a etl::chrono::duration literal representing
/// nanoseconds. Floating-point literal, returns a floating-point
/// duration equivalent to etl::chrono::nanoseconds.
constexpr auto operator""_ns(long double m)
    -> etl::chrono::duration<long double, etl::nano>
{
    return etl::chrono::duration<long double, etl::nano>(m);
}

} // namespace chrono_literals
} // namespace literals
namespace chrono {
using namespace ::etl::literals::chrono_literals;
}
} // namespace etl
#endif // TETL_CHRONO_HPP