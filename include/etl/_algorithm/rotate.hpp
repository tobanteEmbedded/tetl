// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_ROTATE_HPP
#define TETL_ALGORITHM_ROTATE_HPP

#include <etl/_algorithm/iter_swap.hpp>

namespace etl {

/// \brief Performs a left rotation on a range of elements.
/// \details Specifically, rotate swaps the elements in the range [first,
/// last) in such a way that the element n_first becomes the first element of
/// the new range and n_first - 1 becomes the last element. A precondition of
/// this function is that [first, n_first) and [n_first, last) are valid ranges.
/// \ingroup algorithm
template <typename ForwardIt>
constexpr auto rotate(ForwardIt first, ForwardIt nFirst, ForwardIt last) -> ForwardIt
{
    if (first == nFirst) {
        return last;
    }
    if (nFirst == last) {
        return first;
    }

    auto read     = nFirst;
    auto write    = first;
    auto nextRead = first;

    while (read != last) {
        if (write == nextRead) {
            nextRead = read;
        }
        etl::iter_swap(write++, read++);
    }

    etl::rotate(write, nextRead, last);
    return write;
}

} // namespace etl

#endif // TETL_ALGORITHM_ROTATE_HPP
