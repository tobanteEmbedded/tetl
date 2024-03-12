// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_IS_PARTITIONED_HPP
#define TETL_ALGORITHM_IS_PARTITIONED_HPP

namespace etl {

/// \brief Returns true if all elements in the range `[first, last)` that
/// satisfy the predicate p appear before all elements that don't. Also returns
/// true if the range is empty.
/// https://en.cppreference.com/w/cpp/algorithm/is_partitioned
template <typename InputIt, typename Predicate>
[[nodiscard]] constexpr auto is_partitioned(InputIt first, InputIt last, Predicate p) -> bool
{
    for (; first != last; ++first) {
        if (!p(*first)) {
            break;
        }
    }

    for (; first != last; ++first) {
        if (p(*first)) {
            return false;
        }
    }

    return true;
}

} // namespace etl

#endif // TETL_ALGORITHM_IS_PARTITIONED_HPP
