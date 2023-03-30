// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_IS_PERMUTATION_HPP
#define TETL_ALGORITHM_IS_PERMUTATION_HPP

#include "etl/_algorithm/count.hpp"
#include "etl/_algorithm/find.hpp"
#include "etl/_algorithm/mismatch.hpp"
#include "etl/_iterator/distance.hpp"
#include "etl/_iterator/next.hpp"

namespace etl {

/// \brief Returns true if there exists a permutation of the elements in the
/// range `[first1, last1)` that makes that range equal to the range `[first2,
/// last2)`, where `last2` denotes `first2 + (last1 - first1)` if it was not
/// given.
template <typename ForwardIt1, typename ForwardIt2>
[[nodiscard]] constexpr auto is_permutation(ForwardIt1 first, ForwardIt1 last, ForwardIt2 first2) -> bool
{
    // skip common prefix
    auto const [fDiff1, fDiff2] = mismatch(first, last, first2);

    // iterate over the rest, counting how many times each element
    // from `[first, last)` appears in [first2, last2)
    if (fDiff1 != last) {
        auto last2 = next(fDiff2, distance(fDiff1, last));
        for (auto i = fDiff1; i != last; ++i) {
            // this *i has been checked
            if (i != find(fDiff1, i, *i)) { continue; }

            auto m = count(fDiff2, last2, *i);
            if (m == 0 || count(i, last, *i) != m) { return false; }
        }
    }

    return true;
}

template <typename ForwardIt1, typename ForwardIt2>
[[nodiscard]] constexpr auto is_permutation(ForwardIt1 first1, ForwardIt1 last1, ForwardIt2 first2, ForwardIt2 last2)
    -> bool
{
    if (distance(first1, last1) != distance(first2, last2)) { return false; }
    return is_permutation(first1, last1, first2);
}

} // namespace etl

#endif // TETL_ALGORITHM_IS_PERMUTATION_HPP
