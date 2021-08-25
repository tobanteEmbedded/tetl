/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_NONE_OF_HPP
#define TETL_ALGORITHM_NONE_OF_HPP

#include "etl/_algorithm/find_if.hpp"

namespace etl {

/// \brief Checks if unary predicate p returns true for no elements in the range
/// `[first, last)`.
/// \complexity At most `last - first` applications of the predicate.
///
/// \module Algorithm
template <typename InputIt, typename Predicate>
[[nodiscard]] constexpr auto none_of(InputIt first, InputIt last, Predicate p)
    -> bool
{
    return find_if(first, last, p) == last;
}

} // namespace etl

#endif // TETL_ALGORITHM_NONE_OF_HPP