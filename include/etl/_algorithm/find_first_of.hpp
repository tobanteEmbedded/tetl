// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_FIND_FIRST_OF_HPP
#define TETL_ALGORITHM_FIND_FIRST_OF_HPP

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
/// https://en.cppreference.com/w/cpp/algorithm/find_first_of
template <typename InputIt, typename ForwardIt, typename Predicate>
[[nodiscard]] constexpr auto
find_first_of(InputIt first, InputIt last, ForwardIt sFirst, ForwardIt sLast, Predicate pred) -> InputIt
{
    for (; first != last; ++first) {
        for (auto it = sFirst; it != sLast; ++it) {
            if (pred(*first, *it)) {
                return first;
            }
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
/// https://en.cppreference.com/w/cpp/algorithm/find_first_of
template <typename InputIt, typename ForwardIt>
[[nodiscard]] constexpr auto find_first_of(InputIt first, InputIt last, ForwardIt sFirst, ForwardIt sLast) -> InputIt
{
    auto const eq = [](auto const& l, auto const& r) { return l == r; };
    return find_first_of(first, last, sFirst, sLast, eq);
}

} // namespace etl

#endif // TETL_ALGORITHM_FIND_FIRST_OF_HPP
