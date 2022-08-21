/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_COUNT_HPP
#define TETL_ALGORITHM_COUNT_HPP

#include "etl/_iterator/iterator_traits.hpp"

namespace etl {

/// \brief Returns the number of elements in the range `[first, last)`
/// satisfying specific criteria. Counts the elements that are equal to value.
///
/// \param first The range of elements to examine.
/// \param last The range of elements to examine.
/// \param value The value to search for.
///
/// \complexity Exactly `last - first` comparisons / applications of the
/// predicate.
///
/// https://en.cppreference.com/w/cpp/algorithm/count
template <typename InputIt, typename T>
[[nodiscard]] constexpr auto count(InputIt first, InputIt last, T const& value) ->
    typename iterator_traits<InputIt>::difference_type
{
    auto result = typename iterator_traits<InputIt>::difference_type { 0 };
    for (; first != last; ++first) {
        if (*first == value) { ++result; }
    }
    return result;
}

} // namespace etl

#endif // TETL_ALGORITHM_COUNT_HPP
