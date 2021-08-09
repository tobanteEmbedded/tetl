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

#ifndef TETL_DETAIL_ALGORITHM_SEARCH_N_HPP
#define TETL_DETAIL_ALGORITHM_SEARCH_N_HPP

namespace etl {

/// \brief Searches the range `[first, last)` for the first sequence of count
/// identical elements, each equal to the given value.
/// \group search_n
/// \module Algorithm
template <typename ForwardIt, typename Size, typename ValueT,
    typename Predicate>
[[nodiscard]] constexpr auto search_n(ForwardIt first, ForwardIt last,
    Size count, ValueT const& value, Predicate pred) -> ForwardIt
{
    if (count <= Size {}) { return first; }

    auto localCounter = Size {};
    ForwardIt found   = nullptr;

    for (; first != last; ++first) {
        if (pred(*first, value)) {
            localCounter++;
            if (found == nullptr) { found = first; }
        } else {
            localCounter = 0;
        }

        if (localCounter == count) { return found; }
    }

    return last;
}

/// \group search_n
template <typename ForwardIt, typename Size, typename ValueT>
[[nodiscard]] constexpr auto search_n(ForwardIt first, ForwardIt last,
    Size count, ValueT const& value) -> ForwardIt
{
    auto const eq = [](auto const& l, auto const& r) { return l == r; };
    return search_n(first, last, count, value, eq);
}

} // namespace etl

#endif // TETL_DETAIL_ALGORITHM_SEARCH_N_HPP