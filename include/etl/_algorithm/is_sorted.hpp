/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_IS_SORTED_HPP
#define TETL_ALGORITHM_IS_SORTED_HPP

#include "etl/_algorithm/is_sorted_until.hpp"

namespace etl {

/// \brief Checks if the elements in range `[first, last)` are sorted in
/// non-descending order.
template <typename ForwardIt>
[[nodiscard]] constexpr auto is_sorted(ForwardIt first, ForwardIt last) -> bool
{
    return is_sorted_until(first, last) == last;
}

template <typename ForwardIt, typename Compare>
[[nodiscard]] constexpr auto is_sorted(ForwardIt first, ForwardIt last, Compare comp) -> bool
{
    return is_sorted_until(first, last, comp) == last;
}

} // namespace etl

#endif // TETL_ALGORITHM_IS_SORTED_HPP
