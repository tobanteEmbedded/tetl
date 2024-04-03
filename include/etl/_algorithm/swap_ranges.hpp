// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_SWAP_RANGES_HPP
#define TETL_ALGORITHM_SWAP_RANGES_HPP

#include <etl/_algorithm/iter_swap.hpp>

namespace etl {

/// \brief Exchanges elements between range `[first1 ,last1)` and another range
/// starting at `first2`.
///
/// \param first1 The first range of elements to swap.
/// \param last1 The first range of elements to swap.
/// \param first2 Beginning of the second range of elements to swap.
///
/// \returns Iterator to the element past the last element exchanged in the
/// range beginning with `first2`.
///
/// https://en.cppreference.com/w/cpp/algorithm/swap_ranges
///
/// \ingroup algorithm
template <typename ForwardIt1, typename ForwardIt2>
constexpr auto swap_ranges(ForwardIt1 first1, ForwardIt1 last1, ForwardIt2 first2) -> ForwardIt2
{
    while (first1 != last1) {
        etl::iter_swap(first1, first2);
        ++first1;
        ++first2;
    }

    return first2;
}

} // namespace etl

#endif // TETL_ALGORITHM_SWAP_RANGES_HPP
