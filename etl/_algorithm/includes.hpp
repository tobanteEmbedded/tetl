/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_INCLUDES_HPP
#define TETL_ALGORITHM_INCLUDES_HPP

namespace etl {

/// \brief Returns true if the sorted range `[first2, last2)` is a subsequence
/// of the sorted range `[first1, last1)`. Both ranges must be sorted.
template <typename InputIt1, typename InputIt2>
[[nodiscard]] constexpr auto includes(InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2) -> bool
{
    for (; first2 != last2; ++first1) {
        if (first1 == last1 || *first2 < *first1) { return false; }
        if (!(*first1 < *first2)) { ++first2; }
    }
    return true;
}

template <typename InputIt1, typename InputIt2, typename Compare>
[[nodiscard]] constexpr auto includes(InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2, Compare comp)
    -> bool
{
    for (; first2 != last2; ++first1) {
        if (first1 == last1 || comp(*first2, *first1)) { return false; }
        if (!comp(*first1, *first2)) { ++first2; }
    }
    return true;
}

} // namespace etl

#endif // TETL_ALGORITHM_INCLUDES_HPP