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