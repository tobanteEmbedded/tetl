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

#ifndef TETL_CHRONO_DURATION_VALUES_HPP
#define TETL_CHRONO_DURATION_VALUES_HPP

#include "etl/_limits/numeric_limits.hpp"

namespace etl::chrono {
/// \brief The etl::chrono::duration_values type defines three common durations.
/// \details The zero, min, and max methods in etl::chrono::duration forward
/// their work to these methods. This type can be specialized if the
/// representation Rep requires a specific implementation to return these
/// duration objects.
template <typename Rep>
struct duration_values {
public:
    /// \brief Returns a zero-length representation.
    [[nodiscard]] static constexpr auto zero() -> Rep { return Rep {}; }

    /// \brief Returns the smallest possible representation.
    [[nodiscard]] static constexpr auto min() -> Rep
    {
        return etl::numeric_limits<Rep>::lowest();
    }

    /// \brief Returns the special duration value max.
    [[nodiscard]] static constexpr auto max() -> Rep
    {
        return etl::numeric_limits<Rep>::max();
    }
};

} // namespace etl::chrono

#endif // TETL_CHRONO_DURATION_VALUES_HPP