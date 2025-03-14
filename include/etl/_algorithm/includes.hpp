// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_INCLUDES_HPP
#define TETL_ALGORITHM_INCLUDES_HPP

#include <etl/_functional/less.hpp>

namespace etl {

/// \brief Returns true if the sorted range `[first2, last2)` is a subsequence
/// of the sorted range `[first1, last1)`. Both ranges must be sorted.
/// \ingroup algorithm
template <typename InputIt1, typename InputIt2, typename Compare>
[[nodiscard]] constexpr auto includes(InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2, Compare comp)
    -> bool
{
    for (; first2 != last2; ++first1) {
        if (first1 == last1 or comp(*first2, *first1)) {
            return false;
        }
        if (not comp(*first1, *first2)) {
            ++first2;
        }
    }
    return true;
}

/// \ingroup algorithm
template <typename InputIt1, typename InputIt2>
[[nodiscard]] constexpr auto includes(InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2) -> bool
{
    return etl::includes(first1, last1, first2, last2, etl::less());
}

} // namespace etl

#endif // TETL_ALGORITHM_INCLUDES_HPP
