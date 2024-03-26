// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_PARTITION_HPP
#define TETL_ALGORITHM_PARTITION_HPP

#include <etl/_algorithm/find_if_not.hpp>
#include <etl/_algorithm/iter_swap.hpp>
#include <etl/_iterator/next.hpp>

namespace etl {

/// \brief Reorders the elements in the range `[first, last)` in such a way that
/// all elements for which the predicate p returns true precede the elements for
/// which predicate p returns false. Relative order of the elements is not
/// preserved.
template <typename ForwardIt, typename Predicate>
constexpr auto partition(ForwardIt first, ForwardIt last, Predicate p) -> ForwardIt
{
    first = etl::find_if_not(first, last, p);
    if (first == last) {
        return first;
    }

    for (ForwardIt i = etl::next(first); i != last; ++i) {
        if (p(*i)) {
            etl::iter_swap(i, first);
            ++first;
        }
    }
    return first;
}

} // namespace etl

#endif // TETL_ALGORITHM_PARTITION_HPP
