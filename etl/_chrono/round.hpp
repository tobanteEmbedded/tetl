/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CHRONO_ROUND_HPP
#define TETL_CHRONO_ROUND_HPP

#include "etl/_chrono/duration_cast.hpp"
#include "etl/_chrono/time_point_cast.hpp"
#include "etl/_concepts/requires.hpp"
#include "etl/_type_traits/is_arithmetic.hpp"

namespace etl::chrono {

template <typename To, typename Rep, typename Period,
    TETL_REQUIRES_(detail::is_duration<To>::value)>
[[nodiscard]] constexpr auto round(duration<Rep, Period> const& dur) noexcept(
    is_arithmetic_v<Rep>&& is_arithmetic_v<typename To::rep>) -> To
{
    auto const low      = floor<To>(dur);
    auto const high     = low + To { 1 };
    auto const lowDiff  = dur - low;
    auto const highDiff = high - dur;
    if (lowDiff < highDiff) { return low; }
    if (lowDiff > highDiff) { return high; }
    return low.count() & 1 ? high : low;
}

template <typename To, typename Clock, typename Duration,
    TETL_REQUIRES_(detail::is_duration<To>::value)>
[[nodiscard]] constexpr auto round(time_point<Clock, Duration> const& tp)
    -> time_point<Clock, To>
{
    return time_point<Clock, To> { round<To>(tp.time_since_epoch()) };
}

} // namespace etl::chrono

#endif // TETL_CHRONO_ROUND_HPP