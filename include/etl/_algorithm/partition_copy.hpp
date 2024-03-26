// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_PARTITION_COPY_HPP
#define TETL_ALGORITHM_PARTITION_COPY_HPP

#include "etl/_utility/pair.hpp"

namespace etl {

/// \brief Copies the elements from the range `[first, last)` to two different
/// ranges depending on the value returned by the predicate p. The elements that
/// satisfy the predicate p are copied to the range beginning at
/// destination_true. The rest of the elements are copied to the range beginning
/// at destination_false.
/// \details The behavior is undefined if the input range overlaps either of the
/// output ranges.
template <typename InputIt, typename OutputIt1, typename OutputIt2, typename Predicate>
constexpr auto
partition_copy(InputIt first, InputIt last, OutputIt1 destinationTrue, OutputIt2 destinationFalse, Predicate p)
    -> pair<OutputIt1, OutputIt2>
{
    for (; first != last; ++first) {
        if (p(*first)) {
            *destinationTrue = *first;
            ++destinationTrue;
        } else {
            *destinationFalse = *first;
            ++destinationFalse;
        }
    }

    return {destinationTrue, destinationFalse};
}

} // namespace etl

#endif // TETL_ALGORITHM_PARTITION_COPY_HPP
