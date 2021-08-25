/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_REMOVE_HPP
#define TETL_ALGORITHM_REMOVE_HPP

#include "etl/_algorithm/remove_if.hpp"

namespace etl {

/// \brief Removes all elements satisfying specific criteria from the range
/// `[first, last)` and returns a past-the-end iterator for the new end of the
/// range.
/// \group remove
/// \module Algorithm
template <typename ForwardIt, typename T>
[[nodiscard]] constexpr auto remove(
    ForwardIt first, ForwardIt last, T const& value) -> ForwardIt
{
    return remove_if(
        first, last, [&value](auto const& item) { return item == value; });
}

} // namespace etl

#endif // TETL_ALGORITHM_REMOVE_HPP