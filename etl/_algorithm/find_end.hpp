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

#ifndef TETL_ALGORITHM_FIND_END_HPP
#define TETL_ALGORITHM_FIND_END_HPP

#include "etl/_algorithm/search.hpp"
#include "etl/_functional/equal_to.hpp"

namespace etl {

/// \brief Searches for the last occurrence of the sequence [sFirst, sLast) in
/// the range `[first, last)`. Elements are compared using the given binary
/// predicate p.
/// \param first The range of elements to examine
/// \param last The range of elements to examine
/// \param sFirst The range of elements to search for
/// \param sLast The range of elements to search for
/// \param p Binary predicate
/// \returns Iterator to the beginning of last occurrence of the sequence
/// [sFirst, sLast) in range `[first, last)`. If [sFirst, sLast) is empty or if
/// no such sequence is found, last is returned.
/// \group find_end
/// \module Algorithm
template <typename ForwardIt1, typename ForwardIt2, typename Predicate>
[[nodiscard]] constexpr auto find_end(ForwardIt1 first, ForwardIt1 last,
    ForwardIt2 sFirst, ForwardIt2 sLast, Predicate p) -> ForwardIt1
{
    if (sFirst == sLast) { return last; }
    auto result = last;
    while (true) {
        auto newResult = search(first, last, sFirst, sLast, p);
        if (newResult == last) { break; }
        result = newResult;
        first  = result;
        ++first;
    }
    return result;
}

/// \group find_end
template <typename ForwardIt1, typename ForwardIt2>
[[nodiscard]] constexpr auto find_end(ForwardIt1 first, ForwardIt1 last,
    ForwardIt2 sFirst, ForwardIt2 sLast) -> ForwardIt1
{
    return find_end(first, last, sFirst, sLast, equal_to<> {});
}

} // namespace etl

#endif // TETL_ALGORITHM_FIND_END_HPP