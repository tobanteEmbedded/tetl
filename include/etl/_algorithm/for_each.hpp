// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_FOR_EACH_HPP
#define TETL_ALGORITHM_FOR_EACH_HPP

namespace etl {

/// \brief Applies the given function object f to the result of dereferencing
/// every iterator in the range `[first, last)` in order.
///
/// \param first The range to apply the function to.
/// \param last The range to apply the function to.
/// \param f Function object, to be applied to the result of dereferencing every
/// iterator in the range.
///
/// \complexity Exactly `last - first` applications of f.
///
/// https://en.cppreference.com/w/cpp/algorithm/for_each
template <typename InputIt, typename UnaryFunc>
constexpr auto for_each(InputIt first, InputIt last, UnaryFunc f) noexcept -> UnaryFunc
{
    for (; first != last; ++first) {
        f(*first);
    }
    return f;
}

} // namespace etl

#endif // TETL_ALGORITHM_FOR_EACH_HPP
