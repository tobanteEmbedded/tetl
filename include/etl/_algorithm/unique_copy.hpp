// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_UNIQUE_COPY_HPP
#define TETL_ALGORITHM_UNIQUE_COPY_HPP

#include <etl/_functional/equal_to.hpp>

namespace etl {

/// \ingroup algorithm
/// @{

/// Copies the elements from the range `[first, last)`, to another range
/// beginning at d_first in such a way that there are no consecutive equal
/// elements. Only the first element of each group of equal elements is copied.
///
/// Elements are compared using the given binary predicate pred. The behavior
/// is undefined if it is not an equivalence relation.
template <typename InputIt, typename OutputIt, typename Predicate>
constexpr auto unique_copy(InputIt first, InputIt last, OutputIt destination, Predicate pred) -> OutputIt
{
    if (first != last) {
        *destination = *first;

        while (++first != last) {
            if (not pred(*destination, *first)) {
                *++destination = *first;
            }
        }

        ++destination;
    }

    return destination;
}

template <typename InputIt, typename OutputIt>
constexpr auto unique_copy(InputIt first, InputIt last, OutputIt destination) -> OutputIt
{
    return etl::unique_copy(first, last, destination, etl::equal_to());
}

/// @}

} // namespace etl

#endif // TETL_ALGORITHM_UNIQUE_COPY_HPP
