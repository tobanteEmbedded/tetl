// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_REVERSE_HPP
#define TETL_ALGORITHM_REVERSE_HPP

#include "etl/_algorithm/iter_swap.hpp"

namespace etl {

/// \brief Reverses the order of the elements in the range `[first, last)`.
/// Behaves as if applying iter_swap to every pair of iterators `first + i`,
/// `(last-i) - 1` for each non-negative `i < (last - first) / 2`.
template <typename BidirIt>
constexpr auto reverse(BidirIt first, BidirIt last) -> void
{
    while ((first != last) and (first != --last)) { iter_swap(first++, last); }
}

} // namespace etl

#endif // TETL_ALGORITHM_REVERSE_HPP
