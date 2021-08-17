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

#ifndef TETL_CHRONO_ABS_HPP
#define TETL_CHRONO_ABS_HPP

#include "etl/_chrono/duration_cast.hpp"
#include "etl/_chrono/time_point_cast.hpp"
#include "etl/_concepts/requires.hpp"
#include "etl/_limits/numeric_limits.hpp"
#include "etl/_type_traits/is_arithmetic.hpp"

namespace etl::chrono {

/// \brief Returns the absolute value of the duration d. Specifically, if d >=
/// d.zero(), return d, otherwise return -d. The function does not participate
/// in the overload resolution unless etl::numeric_limits<R>::is_signed is
/// true.
template <typename R, typename P, TETL_REQUIRES_(numeric_limits<R>::is_signed)>
constexpr auto abs(duration<R, P> d) noexcept(is_arithmetic_v<R>)
    -> duration<R, P>
{
    return d < duration<R, P>::zero() ? duration<R, P>::zero() - d : d;
}

} // namespace etl::chrono

#endif // TETL_CHRONO_ABS_HPP