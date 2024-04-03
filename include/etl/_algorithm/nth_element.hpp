// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_NTH_ELEMENT_HPP
#define TETL_ALGORITHM_NTH_ELEMENT_HPP

#include <etl/_algorithm/sort.hpp>
#include <etl/_utility/ignore_unused.hpp>

namespace etl {

/// \brief nth_element is a partial sorting algorithm that rearranges elements
/// in `[first, last)` such that:
/// - The element pointed at by nth is changed to whatever element would occur
/// in that position if `[first, last)` were sorted.
/// - All of the elements before this new nth element are less than or equal to
/// the elements after the new nth element.
///
/// https://en.cppreference.com/w/cpp/algorithm/nth_element
///
/// \ingroup algorithm
template <typename RandomIt, typename Compare>
constexpr auto nth_element(RandomIt first, RandomIt nth, RandomIt last, Compare comp) -> void
{
    // TODO: Improve. Currently forwards to regular sort.
    etl::ignore_unused(nth);
    etl::sort(first, last, comp);
}

template <typename RandomIt>
constexpr auto nth_element(RandomIt first, RandomIt nth, RandomIt last) -> void
{
    etl::ignore_unused(nth);
    etl::sort(first, last);
}

} // namespace etl

#endif // TETL_ALGORITHM_NTH_ELEMENT_HPP
