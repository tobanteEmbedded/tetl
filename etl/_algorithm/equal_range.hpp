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

#ifndef TETL_ALGORITHM_EQUAL_RANGE_HPP
#define TETL_ALGORITHM_EQUAL_RANGE_HPP

#include "etl/_algorithm/lower_bound.hpp"
#include "etl/_algorithm/upper_bound.hpp"
#include "etl/_utility/pair.hpp"

namespace etl {

/// \brief Returns a range containing all elements equivalent to value in the
/// range `[first, last)`.
///
/// \notes
/// [cppreference.com/w/cpp/algorithm/equal_range](https://en.cppreference.com/w/cpp/algorithm/equal_range)
///
/// \group equal_range
/// \module Algorithm
template <typename ForwardIt, typename T, typename Compare>
[[nodiscard]] constexpr auto equal_range(ForwardIt first, ForwardIt last,
    T const& value, Compare comp) -> pair<ForwardIt, ForwardIt>
{
    return make_pair(lower_bound(first, last, value, comp),
        upper_bound(first, last, value, comp));
}

/// \group equal_range
template <typename ForwardIt, typename T>
[[nodiscard]] constexpr auto equal_range(ForwardIt first, ForwardIt last,
    T const& value) -> pair<ForwardIt, ForwardIt>
{
    return equal_range(first, last, value, less<> {});
}

} // namespace etl

#endif // TETL_ALGORITHM_EQUAL_RANGE_HPP