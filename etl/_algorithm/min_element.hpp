/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_MIN_ELEMENT_HPP
#define TETL_ALGORITHM_MIN_ELEMENT_HPP

namespace etl {

/// \brief Finds the smallest element in the range `[first, last)`. Elements are
/// compared using operator<.
/// \group min_element
/// \module Algorithm
template <typename ForwardIt>
[[nodiscard]] constexpr auto min_element(
    ForwardIt first, ForwardIt last) noexcept -> ForwardIt
{
    if (first == last) { return last; }

    ForwardIt smallest = first;
    ++first;
    for (; first != last; ++first) {
        if (*first < *smallest) { smallest = first; }
    }
    return smallest;
}

/// \brief Finds the smallest element in the range `[first, last)`. Elements are
/// compared using the given binary comparison function comp.
/// \group min_element
/// \module Algorithm
template <typename ForwardIt, typename Compare>
[[nodiscard]] constexpr auto min_element(
    ForwardIt first, ForwardIt last, Compare comp) -> ForwardIt
{
    if (first == last) { return last; }

    ForwardIt smallest = first;
    ++first;
    for (; first != last; ++first) {
        if (comp(*first, *smallest)) { smallest = first; }
    }
    return smallest;
}

} // namespace etl

#endif // TETL_ALGORITHM_MIN_ELEMENT_HPP