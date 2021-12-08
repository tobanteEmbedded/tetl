/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_UNIQUE_COPY_HPP
#define TETL_ALGORITHM_UNIQUE_COPY_HPP

#include "etl/_functional/equal_to.hpp"

namespace etl {

/// \brief Copies the elements from the range `[first, last)`, to another range
/// beginning at d_first in such a way that there are no consecutive equal
/// elements. Only the first element of each group of equal elements is copied.
/// \details Elements are compared using the given binary predicate pred. The
/// behavior is undefined if it is not an equivalence relation.
/// \group unique_copy
/// \module Algorithm
template <typename InputIt, typename OutputIt, typename Predicate>
constexpr auto unique_copy(InputIt first, InputIt last, OutputIt destination, Predicate pred) -> OutputIt
{
    if (first != last) {
        *destination = *first;

        while (++first != last) {
            if (!pred(*destination, *first)) { *++destination = *first; }
        }

        ++destination;
    }

    return destination;
}

/// \brief Copies the elements from the range `[first, last)`, to another range
/// beginning at d_first in such a way that there are no consecutive equal
/// elements. Only the first element of each group of equal elements is copied.
/// \details Elements are compared using operator==. The behavior is undefined
/// if it is not an equivalence relation.
/// \group unique_copy
/// \module Algorithm
template <typename InputIt, typename OutputIt>
constexpr auto unique_copy(InputIt first, InputIt last, OutputIt destination) -> OutputIt
{
    return unique_copy(first, last, destination, equal_to<> {});
}

} // namespace etl

#endif // TETL_ALGORITHM_UNIQUE_COPY_HPP