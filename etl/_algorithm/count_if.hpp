/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_COUNT_IF_HPP
#define TETL_ALGORITHM_COUNT_IF_HPP

#include "etl/_iterator/iterator_traits.hpp"

namespace etl {

/// \brief Returns the number of elements in the range `[first, last)`
/// satisfying specific criteria. Counts elements for which predicate p returns
/// true.
///
/// \param first The range of elements to examine.
/// \param last The range of elements to examine.
/// \param p Unary predicate which returns ​true for the required elements.
///
/// \complexity Exactly `last - first` comparisons / applications of the
/// predicate.
///
/// https://en.cppreference.com/w/cpp/algorithm/count
///
/// \group count
/// \module Algorithm
template <typename InputIt, typename Predicate>
[[nodiscard]] constexpr auto count_if(InputIt first, InputIt last, Predicate p) ->
    typename iterator_traits<InputIt>::difference_type
{
    auto result = typename iterator_traits<InputIt>::difference_type { 0 };
    for (; first != last; ++first) {
        if (p(*first)) { ++result; }
    }
    return result;
}

} // namespace etl

#endif // TETL_ALGORITHM_COUNT_IF_HPP