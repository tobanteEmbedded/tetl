// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_MISMATCH_HPP
#define TETL_ALGORITHM_MISMATCH_HPP

#include <etl/_utility/pair.hpp>

namespace etl {

/// \brief Returns the first mismatching pair of elements from two ranges: one
/// defined by `[first1, last1)` and another defined by [first2,last2). If last2
/// is not provided (overloads (1-4)), it denotes first2 + (last1 - first1).
/// Elements are compared using the given binary predicate pred.
///
/// \param first1 The first range of the elements.
/// \param last1 The first range of the elements.
/// \param first2 The second range of the elements.
/// \param pred Binary predicate which returns ​true if the elements should be
/// treated as equal.
///
/// https://en.cppreference.com/w/cpp/algorithm/mismatch
template <typename InputIt1, typename InputIt2, typename Predicate>
[[nodiscard]] constexpr auto
mismatch(InputIt1 first1, InputIt1 last1, InputIt2 first2, Predicate pred) -> pair<InputIt1, InputIt2>
{
    for (; first1 != last1; ++first1, (void)++first2) {
        if (!pred(*first1, *first2)) {
            break;
        }
    }

    return {first1, first2};
}

template <typename InputIt1, typename InputIt2>
[[nodiscard]] constexpr auto mismatch(InputIt1 first1, InputIt1 last1, InputIt2 first2) -> pair<InputIt1, InputIt2>
{
    return etl::mismatch(first1, last1, first2, etl::equal_to());
}

template <typename InputIt1, typename InputIt2, typename Predicate>
[[nodiscard]] constexpr auto
mismatch(InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2, Predicate pred) -> pair<InputIt1, InputIt2>
{
    for (; first1 != last1 and first2 != last2; ++first1, (void)++first2) {
        if (!pred(*first1, *first2)) {
            break;
        }
    }

    return {first1, first2};
}

template <typename InputIt1, typename InputIt2>
[[nodiscard]] constexpr auto
mismatch(InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2) -> pair<InputIt1, InputIt2>
{
    return etl::mismatch(first1, last1, first2, last2, etl::equal_to());
}

} // namespace etl

#endif // TETL_ALGORITHM_MISMATCH_HPP
