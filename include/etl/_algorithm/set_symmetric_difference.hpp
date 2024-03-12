// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_SET_SYMMETRIC_DIFFERENCE_HPP
#define TETL_ALGORITHM_SET_SYMMETRIC_DIFFERENCE_HPP

#include <etl/_algorithm/copy.hpp>
#include <etl/_functional/less.hpp>

namespace etl {

/// \brief Computes symmetric difference of two sorted ranges: the elements that
/// are found in either of the ranges, but not in both of them are copied to the
/// range beginning at destination. The resulting range is also sorted.
template <typename InputIt1, typename InputIt2, typename OutputIt, typename Compare>
constexpr auto set_symmetric_difference(
    InputIt1 first1,
    InputIt1 last1,
    InputIt2 first2,
    InputIt2 last2,
    OutputIt destination,
    Compare comp
) -> OutputIt
{
    while (first1 != last1) {
        if (first2 == last2) {
            return copy(first1, last1, destination);
        }

        if (comp(*first1, *first2)) {
            *destination++ = *first1++;
        } else {
            if (comp(*first2, *first1)) {
                *destination++ = *first2;
            } else {
                ++first1;
            }
            ++first2;
        }
    }
    return copy(first2, last2, destination);
}

template <typename InputIt1, typename InputIt2, typename OutputIt>
constexpr auto
set_symmetric_difference(InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2, OutputIt dest) -> OutputIt
{
    return set_symmetric_difference(first1, last1, first2, last2, dest, less<>());
}

} // namespace etl

#endif // TETL_ALGORITHM_SET_SYMMETRIC_DIFFERENCE_HPP
