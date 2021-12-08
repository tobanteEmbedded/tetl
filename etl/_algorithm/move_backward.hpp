/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_MOVE_BACKWARD_HPP
#define TETL_ALGORITHM_MOVE_BACKWARD_HPP

#include "etl/_utility/move.hpp"

namespace etl {

/// \brief Moves the elements from the range `[first, last)`, to another range
/// ending at destination. The elements are moved in reverse order (the last
/// element is moved first), but their relative order is preserved.
///
/// \param first The range of elements to move.
/// \param last The range of elements to move.
/// \param destination End of the destination range.
///
/// \returns Iterator in the destination range, pointing at the last element
/// moved.
///
/// https://en.cppreference.com/w/cpp/algorithm/move_backward
///
/// \module Algorithm
template <typename BidirIt1, typename BidirIt2>
constexpr auto move_backward(BidirIt1 first, BidirIt1 last, BidirIt2 destination) -> BidirIt2
{
    for (; first != last;) { *(--destination) = move(*--last); }
    return destination;
}

} // namespace etl

#endif // TETL_ALGORITHM_MOVE_BACKWARD_HPP