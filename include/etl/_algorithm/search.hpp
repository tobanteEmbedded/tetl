// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_SEARCH_HPP
#define TETL_ALGORITHM_SEARCH_HPP

namespace etl {
namespace detail {

template <typename ForwardIter1, typename ForwardIter2, typename BinaryPredicate>
[[nodiscard]] constexpr auto
search_impl(ForwardIter1 first, ForwardIter1 last, ForwardIter2 sFirst, ForwardIter2 sLast, BinaryPredicate pred)
    -> ForwardIter1
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
            if (!pred(*it, *sIt)) {
                break;
            }
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
/// https://en.cppreference.com/w/cpp/algorithm/search
template <typename ForwardIt1, typename ForwardIt2, typename Predicate>
[[nodiscard]] constexpr auto
search(ForwardIt1 first, ForwardIt1 last, ForwardIt2 sFirst, ForwardIt2 sLast, Predicate pred) -> ForwardIt1
{
    return detail::search_impl(first, last, sFirst, sLast, pred);
}

template <typename ForwardIt1, typename ForwardIt2>
[[nodiscard]] constexpr auto
search(ForwardIt1 first, ForwardIt1 last, ForwardIt2 sFirst, ForwardIt2 sLast) -> ForwardIt1
{
    return search(first, last, sFirst, sLast, [](auto const& lhs, auto const& rhs) { return lhs == rhs; });
}

template <typename ForwardIt, typename Searcher>
[[nodiscard]] constexpr auto search(ForwardIt first, ForwardIt last, Searcher const& searcher) -> ForwardIt
{
    return searcher(first, last).first;
}

} // namespace etl

#endif // TETL_ALGORITHM_SEARCH_HPP
