// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_INPLACE_MERGE_HPP
#define TETL_ALGORITHM_INPLACE_MERGE_HPP

#include <etl/_algorithm/move_backward.hpp>
#include <etl/_functional/less.hpp>
#include <etl/_utility/move.hpp>

namespace etl {

/// \brief Merges two consecutive sorted ranges [first, middle)
///        and [middle, last) into one sorted range [first, last).
///
/// \details A sequence [first, last) is said to be sorted with
///          respect to a comparator comp if for any iterator it pointing
//           to the sequence and any non-negative integer n such that it + n
//           is a valid iterator pointing to an element of the sequence,
///          comp(*(it + n), *it) evaluates to false.
///
/// https://en.cppreference.com/w/cpp/algorithm/inplace_merge
template <typename BidirIt, typename Compare>
constexpr auto inplace_merge(BidirIt begin, BidirIt mid, BidirIt end, Compare comp) -> void
{
    auto left  = begin;
    auto right = mid;
    while (left != mid and right != end) {
        if (comp(*right, *left)) {
            auto value = move(*right);
            move_backward(left, mid, mid + 1);
            *left = move(value);
            ++right;
            ++mid;
        } else {
            ++left;
        }
    }
}

template <typename BidirIt>
constexpr auto inplace_merge(BidirIt first, BidirIt mid, BidirIt last) -> void
{
    inplace_merge(first, mid, last, less {});
}

} // namespace etl

#endif // TETL_ALGORITHM_INPLACE_MERGE_HPP
