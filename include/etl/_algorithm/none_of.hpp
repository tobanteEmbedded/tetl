// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_NONE_OF_HPP
#define TETL_ALGORITHM_NONE_OF_HPP

#include "etl/_algorithm/find_if.hpp"

namespace etl {

/// \brief Checks if unary predicate p returns true for no elements in the range `[first, last)`.
/// \ingroup algorithm
template <typename InputIt, typename Predicate>
[[nodiscard]] constexpr auto none_of(InputIt first, InputIt last, Predicate p) -> bool
{
    return etl::find_if(first, last, p) == last;
}

} // namespace etl

#endif // TETL_ALGORITHM_NONE_OF_HPP
