// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_ALL_OF_HPP
#define TETL_ALGORITHM_ALL_OF_HPP

#include <etl/_algorithm/find_if_not.hpp>

namespace etl {
/// \ingroup algorithm-header
/// @{

/// \brief Checks if unary predicate p returns true for all elements in the
/// range `[first, last)`.
/// \complexity At most `last - first` applications of the predicate.
template <typename InputIt, typename Predicate>
[[nodiscard]] constexpr auto all_of(InputIt first, InputIt last, Predicate p) -> bool
{
    return find_if_not(first, last, p) == last;
}

/// @}

} // namespace etl

#endif // TETL_ALGORITHM_ALL_OF_HPP
