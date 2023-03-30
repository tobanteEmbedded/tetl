// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_MAX_ELEMENT_HPP
#define TETL_ALGORITHM_MAX_ELEMENT_HPP

namespace etl {

/// \brief Finds the greatest element in the range `[first, last)`. Elements are
/// compared using operator<.
template <typename ForwardIt>
[[nodiscard]] constexpr auto max_element(ForwardIt first, ForwardIt last) noexcept -> ForwardIt
{
    if (first == last) { return last; }

    ForwardIt largest = first;
    ++first;
    for (; first != last; ++first) {
        if (*largest < *first) { largest = first; }
    }
    return largest;
}

/// \brief Finds the greatest element in the range `[first, last)`. Elements are
/// compared using the given binary comparison function comp.
template <typename ForwardIt, typename Compare>
[[nodiscard]] constexpr auto max_element(ForwardIt first, ForwardIt last, Compare comp) -> ForwardIt
{
    if (first == last) { return last; }

    ForwardIt largest = first;
    ++first;
    for (; first != last; ++first) {
        if (comp(*largest, *first)) { largest = first; }
    }
    return largest;
}

} // namespace etl

#endif // TETL_ALGORITHM_MAX_ELEMENT_HPP
