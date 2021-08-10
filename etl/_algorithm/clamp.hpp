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

#ifndef TETL_ALGORITHM_CLAMP_HPP
#define TETL_ALGORITHM_CLAMP_HPP

#include "etl/_assert/macro.hpp"
#include "etl/_functional/less.hpp"

namespace etl {

/// \brief If v compares less than lo, returns lo; otherwise if hi compares less
/// than v, returns hi; otherwise returns v. Uses operator< to compare the
/// values.
///
/// \group clamp
/// \module Algorithm
template <typename Type>
[[nodiscard]] constexpr auto clamp(
    Type const& v, Type const& lo, Type const& hi) noexcept -> Type const&
{
    return clamp(v, lo, hi, less<Type>());
}
/// \group clamp
/// \module Algorithm
template <typename Type, typename Compare>
[[nodiscard]] constexpr auto clamp(
    Type const& v, Type const& lo, Type const& hi, Compare comp) -> Type const&
{
    TETL_ASSERT(!comp(hi, lo));
    return comp(v, lo) ? lo : comp(hi, v) ? hi : v;
}

} // namespace etl

#endif // TETL_ALGORITHM_CLAMP_HPP