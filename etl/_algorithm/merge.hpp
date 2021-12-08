/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_MERGE_HPP
#define TETL_ALGORITHM_MERGE_HPP

#include "etl/_algorithm/copy.hpp"
#include "etl/_functional/less.hpp"

namespace etl {

/// \brief Merges two sorted ranges `[first1, last1)` and `[first2, last2)` into
/// one sorted range beginning at `destination`.
///
/// \group merge
/// \module Algorithm
template <typename InputIt1, typename InputIt2, typename OutputIt, typename Compare>
constexpr auto merge(
    InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2, OutputIt destination, Compare comp) -> OutputIt
{
    for (; first1 != last1; ++destination) {
        if (first2 == last2) { return copy(first1, last1, destination); }
        if (comp(*first2, *first1)) {
            *destination = *first2;
            ++first2;
        } else {
            *destination = *first1;
            ++first1;
        }
    }
    return copy(first2, last2, destination);
}

/// \group merge
template <typename InputIt1, typename InputIt2, typename OutputIt>
constexpr auto merge(InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2, OutputIt destination) -> OutputIt
{
    return merge(first1, last1, first2, last2, destination, less<> {});
}

} // namespace etl

#endif // TETL_ALGORITHM_MERGE_HPP