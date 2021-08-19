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

#ifndef TETL_CHRONO_FLOOR_HPP
#define TETL_CHRONO_FLOOR_HPP

#include "etl/_chrono/duration_cast.hpp"
#include "etl/_chrono/time_point_cast.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_arithmetic.hpp"

namespace etl::chrono {

/// \brief Returns the greatest duration t representable in ToDuration that is
/// less or equal to d. The function does not participate in the overload
/// resolution unless ToDuration is an instance of etl::chrono::duration.
template <typename To, typename Rep, typename Period>
[[nodiscard]] constexpr auto floor(duration<Rep, Period> const& d) noexcept(
    is_arithmetic_v<Rep>&& is_arithmetic_v<typename To::rep>)
    -> enable_if_t<detail::is_duration_v<To>, To>
{
    auto const t { duration_cast<To>(d) };
    if (t > d) { return To(t.count() - static_cast<typename To::rep>(1)); }
    return t;
}

template <typename To, typename Clock, typename Duration>
[[nodiscard]] constexpr auto floor(time_point<Clock, Duration> const& tp)
    -> enable_if_t<detail::is_duration_v<To>, time_point<Clock, To>>
{
    return time_point<Clock, To>(floor<To>(tp.time_since_epoch()));
}

} // namespace etl::chrono

#endif // TETL_CHRONO_FLOOR_HPP