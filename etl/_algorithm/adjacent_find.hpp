/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_ADJACENT_FIND_HPP
#define TETL_ALGORITHM_ADJACENT_FIND_HPP

#include "etl/_functional/equal_to.hpp"

namespace etl {
/// \ingroup algorithm-header
/// @{

/// \brief Searches the range `[first, last)` for two consecutive equal
/// elements. Elements are compared using the given binary predicate p.
///
/// \param first The range of elements to examine.
/// \param last The range of elements to examine.
/// \param pred Binary predicate which returns ​true if the elements should be
/// treated as equal.
///
/// https://en.cppreference.com/w/cpp/algorithm/adjacent_find
template <typename ForwardIt, typename Predicate>
[[nodiscard]] constexpr auto adjacent_find(ForwardIt first, ForwardIt last, Predicate pred) -> ForwardIt
{
    if (first == last) { return last; }

    auto next = first;
    ++next;

    for (; next != last; ++next, (void)++first) {
        if (pred(*first, *next)) { return first; }
    }

    return last;
}

template <typename ForwardIt>
[[nodiscard]] constexpr auto adjacent_find(ForwardIt first, ForwardIt last) -> ForwardIt
{
    return adjacent_find(first, last, equal_to<> {});
}

/// @}

} // namespace etl

#endif // TETL_ALGORITHM_ADJACENT_FIND_HPP