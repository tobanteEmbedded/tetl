/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_FIND_IF_NOT_HPP
#define TETL_ALGORITHM_FIND_IF_NOT_HPP

namespace etl {

/// \brief Searches for an element for which predicate q returns false
///
/// \param first The range of elements to examine.
/// \param last The range of elements to examine.
/// \param pred Unary predicate which returns ​true for the required element.
///
/// https://en.cppreference.com/w/cpp/algorithm/find
///
/// \group find_if_not
/// \module Algorithm
template <typename InputIt, typename Predicate>
[[nodiscard]] constexpr auto find_if_not(
    InputIt first, InputIt last, Predicate pred) noexcept -> InputIt
{
    for (; first != last; ++first) {
        if (!pred(*first)) { return first; }
    }
    return last;
}

} // namespace etl

#endif // TETL_ALGORITHM_FIND_IF_NOT_HPP