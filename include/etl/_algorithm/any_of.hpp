// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_ANY_OF_HPP
#define TETL_ALGORITHM_ANY_OF_HPP

#include <etl/_algorithm/find_if.hpp>

namespace etl {

/// \ingroup algorithm
/// @{

/// \brief Checks if unary predicate p returns true for at least one element in the range `[first, last)`.
template <typename InputIt, typename Predicate>
[[nodiscard]] constexpr auto any_of(InputIt first, InputIt last, Predicate p) -> bool
{
    return etl::find_if(first, last, p) != last;
}

/// @}

} // namespace etl

#endif // TETL_ALGORITHM_ANY_OF_HPP
