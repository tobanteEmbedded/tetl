// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_ITER_SWAP_HPP
#define TETL_ALGORITHM_ITER_SWAP_HPP

#include "etl/_utility/swap.hpp"

namespace etl {

/// \brief Swaps the values of the elements the given iterators are pointing to.
///
/// \param a Iterators to the elements to swap.
/// \param b Iterators to the elements to swap.
///
/// https://en.cppreference.com/w/cpp/algorithm/iter_swap
template <typename ForwardIt1, typename ForwardIt2>
constexpr auto iter_swap(ForwardIt1 a, ForwardIt2 b) -> void
{
    using etl::swap;
    swap(*a, *b);
}

} // namespace etl

#endif // TETL_ALGORITHM_ITER_SWAP_HPP
