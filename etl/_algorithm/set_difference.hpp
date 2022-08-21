/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_SET_DIFFERENCE_HPP
#define TETL_ALGORITHM_SET_DIFFERENCE_HPP

#include "etl/_algorithm/copy.hpp"
#include "etl/_functional/less.hpp"

namespace etl {

/// \brief Copies the elements from the sorted range `[first1, last1)` which are
/// not found in the sorted range `[first2, last2)` to the range beginning at
/// destination. Elements are compared using the given binary comparison
/// function `comp` and the ranges must be sorted with respect to the same.
template <typename InputIt1, typename InputIt2, typename OutputIt, typename Compare>
constexpr auto set_difference(
    InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2, OutputIt destination, Compare comp) -> OutputIt
{
    while (first1 != last1) {
        if (first2 == last2) { return copy(first1, last1, destination); }

        if (comp(*first1, *first2)) {
            *destination++ = *first1++;
        } else {
            if (!comp(*first2, *first1)) { ++first1; }
            ++first2;
        }
    }
    return destination;
}

template <typename InputIt1, typename InputIt2, typename OutputIt>
constexpr auto set_difference(InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2, OutputIt destination)
    -> OutputIt
{
    return set_difference(first1, last1, first2, last2, destination, less<> {});
}

} // namespace etl

#endif // TETL_ALGORITHM_SET_DIFFERENCE_HPP
