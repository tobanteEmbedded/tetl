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

#ifndef TETL_CHRONO_TIME_POINT_CAST_HPP
#define TETL_CHRONO_TIME_POINT_CAST_HPP

#include "etl/_chrono/duration_cast.hpp"
#include "etl/_chrono/time_point.hpp"
#include "etl/_concepts/requires.hpp"

namespace etl::chrono {

template <typename ToDuration, typename Clock, typename Duration,
    TETL_REQUIRES_(detail::is_duration<ToDuration>::value)>
[[nodiscard]] constexpr auto time_point_cast(
    time_point<Clock, Duration> const& tp) -> ToDuration
{
    using time_point_t = time_point<Clock, ToDuration>;
    return time_point_t(duration_cast<ToDuration>(tp.time_since_epoch()));
}

} // namespace etl::chrono

#endif // TETL_CHRONO_TIME_POINT_CAST_HPP