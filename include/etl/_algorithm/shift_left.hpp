// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_SHIFT_LEFT_HPP
#define TETL_ALGORITHM_SHIFT_LEFT_HPP

#include <etl/_algorithm/move.hpp>
#include <etl/_concepts/emulation.hpp>
#include <etl/_iterator/iterator_traits.hpp>

namespace etl {

/// \brief Shifts the elements in the range [first, last) by n positions.
///
/// \details Shifts the elements towards the beginning of the range. If n == 0
/// or n >= last - first, there are no effects. If n < 0, the behavior is
/// undefined. Otherwise, for every integer i in [0, last - first - n), moves
/// the element originally at position first + n + i to position first + i. The
/// moves are performed in increasing order of i starting from ​0​.
///
/// \ingroup algorithm
template <typename ForwardIt>
constexpr auto
shift_left(ForwardIt first, ForwardIt const last, typename iterator_traits<ForwardIt>::difference_type n) -> ForwardIt
{
    // The standard only checks for n == 0. n < 0 would be undefined behavior.
    // This implementation does nothing if n < 0.
    if (n <= 0) {
        return last;
    }

    auto start = first;
    if constexpr (etl::detail::RandomAccessIterator<ForwardIt>) {
        if (n >= last - first) {
            return first;
        }
        start += n;
    } else {
        for (; 0 < n; --n) {
            if (start == last) {
                return first;
            }
            ++start;
        }
    }

    first = etl::move(start, last, first);
    return first;
}

} // namespace etl

#endif // TETL_ALGORITHM_SHIFT_LEFT_HPP
