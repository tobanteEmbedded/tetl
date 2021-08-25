/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_REMOVE_IF_HPP
#define TETL_ALGORITHM_REMOVE_IF_HPP

#include "etl/_algorithm/find_if.hpp"
#include "etl/_utility/move.hpp"

namespace etl {

/// \brief Removes all elements satisfying specific criteria from the range
/// `[first, last)` and returns a past-the-end iterator for the new end of the
/// range.
/// \group remove_if
/// \module Algorithm
template <typename ForwardIt, typename Predicate>
[[nodiscard]] constexpr auto remove_if(
    ForwardIt first, ForwardIt last, Predicate pred) -> ForwardIt
{
    first = find_if(first, last, pred);

    if (first != last) {
        for (auto i = first; ++i != last;) {
            if (!pred(*i)) { *first++ = move(*i); }
        }
    }

    return first;
}

} // namespace etl

#endif // TETL_ALGORITHM_REMOVE_IF_HPP