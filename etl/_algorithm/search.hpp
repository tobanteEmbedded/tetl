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

#ifndef TETL_ALGORITHM_SEARCH_HPP
#define TETL_ALGORITHM_SEARCH_HPP

namespace etl {
namespace detail {

template <typename ForwardIter1, typename ForwardIter2,
    typename BinaryPredicate>
[[nodiscard]] constexpr auto search_impl(ForwardIter1 first, ForwardIter1 last,
    ForwardIter2 sFirst, ForwardIter2 sLast, BinaryPredicate pred)
    -> ForwardIter1
{
    for (;; ++first) {
        auto it = first;
        for (auto sIt = sFirst;; ++it, (void)++sIt) {
            if (sIt == sLast) { return first; }
            if (it == last) { return last; }
            if (!pred(*it, *sIt)) { break; }
        }
    }
}
} // namespace detail

/// \brief Searches for the first occurrence of the sequence of elements
/// [sFirst, sLast) in the range `[first, last)`.
///
/// \param first The range of elements to examine.
/// \param last The range of elements to examine.
/// \param sFirst The range of elements to search for.
/// \param sLast The range of elements to search for.
/// \param pred Binary predicate which returns ​true if the elements should be
/// treated as equal.
///
/// \notes
/// [cppreference.com/w/cpp/algorithm/search](https://en.cppreference.com/w/cpp/algorithm/search)
///
/// \group search
/// \module Algorithm
template <typename ForwardIt1, typename ForwardIt2, typename Predicate>
[[nodiscard]] constexpr auto search(ForwardIt1 first, ForwardIt1 last,
    ForwardIt2 sFirst, ForwardIt2 sLast, Predicate pred) -> ForwardIt1
{
    return detail::search_impl(first, last, sFirst, sLast, pred);
}

/// \group search
template <typename ForwardIt1, typename ForwardIt2>
[[nodiscard]] constexpr auto search(ForwardIt1 first, ForwardIt1 last,
    ForwardIt2 sFirst, ForwardIt2 sLast) -> ForwardIt1
{
    auto const eq = [](auto const& l, auto const& r) { return l == r; };
    return search(first, last, sFirst, sLast, eq);
}

/// \group search
template <typename ForwardIt, typename Searcher>
[[nodiscard]] constexpr auto search(
    ForwardIt first, ForwardIt last, Searcher const& searcher) -> ForwardIt
{
    return searcher(first, last).first;
}

} // namespace etl

#endif // TETL_ALGORITHM_SEARCH_HPP
