/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_FIND_HPP
#define TETL_ALGORITHM_FIND_HPP

namespace etl {

/// \brief Searches for an element equal to value.
///
/// \param first The range of elements to examine.
/// \param last The range of elements to examine.
/// \param value Value to compare the elements to.
///
/// https://en.cppreference.com/w/cpp/algorithm/find
///
/// \group find
/// \module Algorithm
template <typename InputIt, typename T>
[[nodiscard]] constexpr auto find(
    InputIt first, InputIt last, T const& value) noexcept -> InputIt
{
    for (; first != last; ++first) {
        if (*first == value) { return first; }
    }
    return last;
}

} // namespace etl

#endif // TETL_ALGORITHM_FIND_HPP