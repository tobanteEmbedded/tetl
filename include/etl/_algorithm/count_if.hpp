// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_COUNT_IF_HPP
#define TETL_ALGORITHM_COUNT_IF_HPP

#include <etl/_iterator/iterator_traits.hpp>

namespace etl {

/// \ingroup algorithm-header
/// @{

/// \brief Returns the number of elements in the range `[first, last)`
/// satisfying specific criteria. Counts elements for which predicate p returns
/// true.
///
/// \param first The range of elements to examine.
/// \param last The range of elements to examine.
/// \param p Unary predicate which returns ​true for the required elements.
///
/// https://en.cppreference.com/w/cpp/algorithm/count
template <typename InputIt, typename Predicate>
[[nodiscard]] constexpr auto count_if(InputIt first, InputIt last, Predicate p) ->
    typename iterator_traits<InputIt>::difference_type
{
    auto result = typename iterator_traits<InputIt>::difference_type{0};
    for (; first != last; ++first) {
        if (p(*first)) {
            ++result;
        }
    }
    return result;
}

/// @}

} // namespace etl

#endif // TETL_ALGORITHM_COUNT_IF_HPP
