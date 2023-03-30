// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_FOR_EACH_N_HPP
#define TETL_ALGORITHM_FOR_EACH_N_HPP

namespace etl {

/// \brief Applies the given function object f to the result of dereferencing
/// every iterator in the range `[first, first + n]` in order.
///
/// \param first The beginning of the range to apply the function to.
/// \param n The number of elements to apply the function to.
/// \param f Function object, to be applied to the result of dereferencing every
/// iterator in the range.
///
/// \complexity Exactly n applications of f.
///
/// https://en.cppreference.com/w/cpp/algorithm/for_each_n
template <typename InputIt, typename Size, typename UnaryFunc>
constexpr auto for_each_n(InputIt first, Size n, UnaryFunc f) noexcept -> InputIt
{
    for (Size i = 0; i < n; ++first, (void)++i) { f(*first); }
    return first;
}

} // namespace etl

#endif // TETL_ALGORITHM_FOR_EACH_N_HPP
