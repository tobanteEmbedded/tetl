// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_SEARCH_HPP
#define TETL_ALGORITHM_SEARCH_HPP

#include <etl/_functional/equal_to.hpp>

namespace etl {

/// \ingroup algorithm
/// @{

/// Searches for the first occurrence of the sequence of elements
/// [sFirst, sLast) in the range `[first, last)`.
///
/// https://en.cppreference.com/w/cpp/algorithm/search
///
/// \param first The range of elements to examine.
/// \param last The range of elements to examine.
/// \param sFirst The range of elements to search for.
/// \param sLast The range of elements to search for.
/// \param pred Binary predicate which returns ​true if the elements should be treated as equal.
template <typename FwdIt1, typename FwdIt2, typename Predicate>
[[nodiscard]] constexpr auto search(FwdIt1 first, FwdIt1 last, FwdIt2 sFirst, FwdIt2 sLast, Predicate pred) -> FwdIt1
{
    for (;; ++first) {
        auto it = first;
        for (auto sIt = sFirst;; ++it, (void)++sIt) {
            if (sIt == sLast) {
                return first;
            }
            if (it == last) {
                return last;
            }
            if (not pred(*it, *sIt)) {
                break;
            }
        }
    }
}

template <typename FwdIt1, typename FwdIt2>
[[nodiscard]] constexpr auto search(FwdIt1 first, FwdIt1 last, FwdIt2 sFirst, FwdIt2 sLast) -> FwdIt1
{
    return etl::search(first, last, sFirst, sLast, etl::equal_to());
}

template <typename FwdIt, typename Searcher>
[[nodiscard]] constexpr auto search(FwdIt first, FwdIt last, Searcher const& searcher) -> FwdIt
{
    return searcher(first, last).first;
}

/// @}

} // namespace etl

#endif // TETL_ALGORITHM_SEARCH_HPP
