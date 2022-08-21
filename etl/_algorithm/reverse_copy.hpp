/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_REVERSE_COPY_HPP
#define TETL_ALGORITHM_REVERSE_COPY_HPP

namespace etl {

/// \brief Copies the elements from the range `[first, last)` to another range
/// beginning at d_first in such a way that the elements in the new range are in
/// reverse order.
/// \details If the source and destination ranges (that is, `[first, last)` and
/// [d_first, d_first+(last-first)) respectively) overlap, the behavior is
/// undefined.
template <typename BidirIt, typename OutputIt>
constexpr auto reverse_copy(BidirIt first, BidirIt last, OutputIt destination) -> OutputIt
{
    for (; first != last; ++destination) { *(destination) = *(--last); }
    return destination;
}

} // namespace etl

#endif // TETL_ALGORITHM_REVERSE_COPY_HPP
