// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_MOVE_BACKWARD_HPP
#define TETL_ALGORITHM_MOVE_BACKWARD_HPP

#include <etl/_utility/move.hpp>

namespace etl {

/// Moves the elements from the range `[first, last)`, to another range
/// ending at destination. The elements are moved in reverse order (the last
/// element is moved first), but their relative order is preserved.
///
/// https://en.cppreference.com/w/cpp/algorithm/move_backward
///
/// \returns Iterator in the destination range, pointing at the last element moved.
///
/// \param first The range of elements to move.
/// \param last The range of elements to move.
/// \param destination End of the destination range.
///
/// \ingroup algorithm
template <typename BidirIt1, typename BidirIt2>
constexpr auto move_backward(BidirIt1 first, BidirIt1 last, BidirIt2 destination) -> BidirIt2
{
    for (; first != last;) {
        --last;
        *(--destination) = TETL_MOVE(*last);
    }
    return destination;
}

} // namespace etl

#endif // TETL_ALGORITHM_MOVE_BACKWARD_HPP
