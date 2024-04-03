// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_REMOVE_HPP
#define TETL_ALGORITHM_REMOVE_HPP

#include "etl/_algorithm/remove_if.hpp"

namespace etl {

/// \brief Removes all elements satisfying specific criteria from the range
/// `[first, last)` and returns a past-the-end iterator for the new end of the
/// range.
/// \ingroup algorithm
template <typename ForwardIt, typename T>
[[nodiscard]] constexpr auto remove(ForwardIt first, ForwardIt last, T const& value) -> ForwardIt
{
    return etl::remove_if(first, last, [&value](auto const& item) { return item == value; });
}

} // namespace etl

#endif // TETL_ALGORITHM_REMOVE_HPP
