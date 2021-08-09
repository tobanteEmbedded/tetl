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

#ifndef TETL_DETAIL_ALGORITHM_FIND_FIRST_OF_HPP
#define TETL_DETAIL_ALGORITHM_FIND_FIRST_OF_HPP

namespace etl {

/// \brief Searches the range `[first, last)` for any of the elements in the
/// range [sFirst, sLast). Elements are compared using the given binary
/// predicate pred.
///
/// \param first The range of elements to examine.
/// \param last The range of elements to examine.
/// \param sFirst The range of elements to search for.
/// \param sLast The range of elements to search for.
/// \param pred Predicate which returns ​true if the elements should be
/// treated as equal.
///
/// \notes
/// [cppreference.com/w/cpp/algorithm/find_first_of](https://en.cppreference.com/w/cpp/algorithm/find_first_of)
///
/// \group find_first_of
/// \module Algorithm
template <typename InputIt, typename ForwardIt, typename Predicate>
[[nodiscard]] constexpr auto find_first_of(InputIt first, InputIt last,
    ForwardIt sFirst, ForwardIt sLast, Predicate pred) -> InputIt
{
    for (; first != last; ++first) {
        for (auto it = sFirst; it != sLast; ++it) {
            if (pred(*first, *it)) { return first; }
        }
    }

    return last;
}

/// \brief Searches the range `[first, last)` for any of the elements in the
/// range [sFirst, sLast).
///
/// \param first The range of elements to examine.
/// \param last The range of elements to examine.
/// \param sFirst The range of elements to search for.
/// \param sLast The range of elements to search for.
///
/// \notes
/// [cppreference.com/w/cpp/algorithm/find_first_of](https://en.cppreference.com/w/cpp/algorithm/find_first_of)
///
/// \group find_first_of
/// \module Algorithm
template <typename InputIt, typename ForwardIt>
[[nodiscard]] constexpr auto find_first_of(
    InputIt first, InputIt last, ForwardIt sFirst, ForwardIt sLast) -> InputIt
{
    auto const eq = [](auto const& l, auto const& r) { return l == r; };
    return find_first_of(first, last, sFirst, sLast, eq);
}

} // namespace etl

#endif // TETL_DETAIL_ALGORITHM_FIND_FIRST_OF_HPP