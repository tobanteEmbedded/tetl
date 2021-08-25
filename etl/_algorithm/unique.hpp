/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_UNIQUE_HPP
#define TETL_ALGORITHM_UNIQUE_HPP

#include "etl/_functional/equal_to.hpp"
#include "etl/_utility/move.hpp"

namespace etl {

/// \brief Eliminates all except the first element from every consecutive group
/// of equivalent elements from the range `[first, last)` and returns a
/// past-the-end iterator for the new logical end of the range.
/// \group unique
/// \module Algorithm
template <typename ForwardIt, typename Predicate>
constexpr auto unique(ForwardIt first, ForwardIt last, Predicate pred)
    -> ForwardIt
{
    if (first == last) { return last; }

    auto result = first;
    while (++first != last) {
        if (!pred(*result, *first) && ++result != first) {
            *result = move(*first);
        }
    }
    return ++result;
}

/// \brief Eliminates all except the first element from every consecutive group
/// of equivalent elements from the range `[first, last)` and returns a
/// past-the-end iterator for the new logical end of the range.
/// \group unique
/// \module Algorithm
template <typename ForwardIt>
constexpr auto unique(ForwardIt first, ForwardIt last) -> ForwardIt
{
    return unique(first, last, equal_to<> {});
}

} // namespace etl

#endif // TETL_ALGORITHM_UNIQUE_HPP