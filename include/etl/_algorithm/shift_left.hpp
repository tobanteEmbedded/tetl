/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_SHIFT_LEFT_HPP
#define TETL_ALGORITHM_SHIFT_LEFT_HPP

#include "etl/_algorithm/move.hpp"
#include "etl/_concepts/emulation.hpp"
#include "etl/_iterator/iterator_traits.hpp"

namespace etl {

/// \brief Shifts the elements in the range [first, last) by n positions.
///
/// \details Shifts the elements towards the beginning of the range. If n == 0
/// || n >= last - first, there are no effects. If n < 0, the behavior is
/// undefined. Otherwise, for every integer i in [0, last - first - n), moves
/// the element originally at position first + n + i to position first + i. The
/// moves are performed in increasing order of i starting from ​0​.
template <typename ForwardIt>
constexpr auto shift_left(ForwardIt first, const ForwardIt last, typename iterator_traits<ForwardIt>::difference_type n)
    -> ForwardIt
{
    if (n <= 0) { return last; }
    auto start = first;
    if constexpr (detail::RandomAccessIterator<ForwardIt>) {
        if (n >= last - first) { return first; }
        start += n;
    } else {
        for (; 0 < n; --n) {
            if (start == last) { return first; }
            ++start;
        }
    }

    first = move(start, last, first);
    return first;
}

} // namespace etl

#endif // TETL_ALGORITHM_SHIFT_LEFT_HPP
