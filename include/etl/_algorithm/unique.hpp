// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_UNIQUE_HPP
#define TETL_ALGORITHM_UNIQUE_HPP

#include <etl/_functional/equal_to.hpp>
#include <etl/_utility/move.hpp>

namespace etl {

/// \ingroup algorithm
/// @{

/// Eliminates all except the first element from every consecutive group
/// of equivalent elements from the range `[first, last)` and returns a
/// past-the-end iterator for the new logical end of the range.
template <typename ForwardIt, typename Predicate>
constexpr auto unique(ForwardIt first, ForwardIt last, Predicate pred) -> ForwardIt
{
    if (first == last) {
        return last;
    }

    auto result = first;
    while (++first != last) {
        if (not pred(*result, *first) and ++result != first) {
            *result = etl::move(*first);
        }
    }
    return ++result;
}

template <typename ForwardIt>
constexpr auto unique(ForwardIt first, ForwardIt last) -> ForwardIt
{
    return etl::unique(first, last, etl::equal_to());
}

/// @}

} // namespace etl

#endif // TETL_ALGORITHM_UNIQUE_HPP
