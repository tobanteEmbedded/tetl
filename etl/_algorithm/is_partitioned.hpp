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

#ifndef TETL_ALGORITHM_IS_PARTITIONED_HPP
#define TETL_ALGORITHM_IS_PARTITIONED_HPP

namespace etl {

/// \brief Returns true if all elements in the range `[first, last)` that
/// satisfy the predicate p appear before all elements that don't. Also returns
/// true if the range is empty.
/// \notes
/// [cppreference.com/w/cpp/algorithm/is_partitioned](https://en.cppreference.com/w/cpp/algorithm/is_partitioned)
///
/// \module Algorithm
template <typename InputIt, typename Predicate>
[[nodiscard]] constexpr auto is_partitioned(
    InputIt first, InputIt last, Predicate p) -> bool
{
    for (; first != last; ++first) {
        if (!p(*first)) { break; }
    }

    for (; first != last; ++first) {
        if (p(*first)) { return false; }
    }

    return true;
}

} // namespace etl

#endif // TETL_ALGORITHM_IS_PARTITIONED_HPP