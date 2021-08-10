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

#ifndef TETL_ALGORITHM_MIN_ELEMENT_HPP
#define TETL_ALGORITHM_MIN_ELEMENT_HPP

namespace etl {

/// \brief Finds the smallest element in the range `[first, last)`. Elements are
/// compared using operator<.
/// \group min_element
/// \module Algorithm
template <typename ForwardIt>
[[nodiscard]] constexpr auto min_element(
    ForwardIt first, ForwardIt last) noexcept -> ForwardIt
{
    if (first == last) { return last; }

    ForwardIt smallest = first;
    ++first;
    for (; first != last; ++first) {
        if (*first < *smallest) { smallest = first; }
    }
    return smallest;
}

/// \brief Finds the smallest element in the range `[first, last)`. Elements are
/// compared using the given binary comparison function comp.
/// \group min_element
/// \module Algorithm
template <typename ForwardIt, typename Compare>
[[nodiscard]] constexpr auto min_element(
    ForwardIt first, ForwardIt last, Compare comp) -> ForwardIt
{
    if (first == last) { return last; }

    ForwardIt smallest = first;
    ++first;
    for (; first != last; ++first) {
        if (comp(*first, *smallest)) { smallest = first; }
    }
    return smallest;
}

} // namespace etl

#endif // TETL_ALGORITHM_MIN_ELEMENT_HPP