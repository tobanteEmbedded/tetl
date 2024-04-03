// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_INPLACE_MERGE_HPP
#define TETL_ALGORITHM_INPLACE_MERGE_HPP

#include <etl/_algorithm/move_backward.hpp>
#include <etl/_functional/less.hpp>
#include <etl/_utility/move.hpp>

namespace etl {

/// Merges two consecutive sorted ranges [first, middle) and
/// [middle, last) into one sorted range [first, last).
///
/// A sequence [first, last) is said to be sorted with respect to
/// a comparator comp if for any iterator it pointing to the sequence
/// and any non-negative integer n such that it + n is a valid
/// iterator pointing to an element of the sequence, comp(*(it + n), *it)
/// evaluates to false.
///
/// https://en.cppreference.com/w/cpp/algorithm/inplace_merge
///
/// \ingroup algorithm
template <typename BidirIt, typename Compare>
constexpr auto inplace_merge(BidirIt begin, BidirIt mid, BidirIt end, Compare comp) -> void
{
    auto left  = begin;
    auto right = mid;
    while (left != mid and right != end) {
        if (comp(*right, *left)) {
            auto value = TETL_MOVE(*right);
            etl::move_backward(left, mid, mid + 1);
            *left = TETL_MOVE(value);
            ++right;
            ++mid;
        } else {
            ++left;
        }
    }
}

/// \ingroup algorithm
template <typename BidirIt>
constexpr auto inplace_merge(BidirIt first, BidirIt mid, BidirIt last) -> void
{
    etl::inplace_merge(first, mid, last, etl::less());
}

} // namespace etl

#endif // TETL_ALGORITHM_INPLACE_MERGE_HPP
