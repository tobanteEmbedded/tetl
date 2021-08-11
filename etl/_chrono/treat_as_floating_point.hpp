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

#ifndef TETL_CHRONO_TREAT_AS_FLOATING_POINT_HPP
#define TETL_CHRONO_TREAT_AS_FLOATING_POINT_HPP

#include "etl/_type_traits/is_floating_point.hpp"

namespace etl::chrono {

/// \brief The etl::chrono::treat_as_floating_point trait helps determine if a
/// duration can be converted to another duration with a different tick period.
/// \details Implicit conversions between two durations normally depends on the
/// tick period of the durations. However, implicit conversions can happen
/// regardless of tick period if
/// etl::chrono::treat_as_floating_point<Rep>::value == true.
/// \note etl::chrono::treat_as_floating_point may be specialized for
/// program-defined types.
/// \group treat_as_floating_point
template <typename Rep>
struct treat_as_floating_point : etl::is_floating_point<Rep> {
};

/// \group treat_as_floating_point
template <typename Rep>
inline constexpr bool treat_as_floating_point_v
    = treat_as_floating_point<Rep>::value;

} // namespace etl::chrono

#endif // TETL_CHRONO_TREAT_AS_FLOATING_POINT_HPP