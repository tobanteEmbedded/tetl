// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_BINARY_SEARCH_HPP
#define TETL_ALGORITHM_BINARY_SEARCH_HPP

#include <etl/_algorithm/lower_bound.hpp>
#include <etl/_functional/less.hpp>

namespace etl {

/// \ingroup algorithm
///@{

/// Checks if an element equivalent to value appears within the range
/// `[first, last)`. For binary_search to succeed, the range `[first, last)`
/// must be at least partially ordered with respect to `value`.
///
/// https://en.cppreference.com/w/cpp/algorithm/binary_search
template <typename ForwardIt, typename T, typename Compare>
[[nodiscard]] constexpr auto binary_search(ForwardIt first, ForwardIt last, T const& value, Compare comp) -> bool
{
    first = etl::lower_bound(first, last, value, comp);
    return (!(first == last) and !(comp(value, *first)));
}

template <typename ForwardIt, typename T>
[[nodiscard]] constexpr auto binary_search(ForwardIt first, ForwardIt last, T const& value) -> bool
{
    return etl::binary_search(first, last, value, etl::less());
}

///@}

} // namespace etl

#endif // TETL_ALGORITHM_BINARY_SEARCH_HPP
