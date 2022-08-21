/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_UPPER_BOUND_HPP
#define TETL_ALGORITHM_UPPER_BOUND_HPP

#include "etl/_functional/less.hpp"
#include "etl/_iterator/advance.hpp"
#include "etl/_iterator/distance.hpp"
#include "etl/_iterator/iterator_traits.hpp"

namespace etl {

/// \brief Returns an iterator pointing to the first element in the range
/// `[first, last)` that is greater than `value`, or last if no such element is
/// found.
///
/// \details The range `[first, last)` must be partitioned with respect to the
/// expression `!(value < element)` or `!comp(value, element)`, i.e., all
/// elements for which the expression is true must precede all elements for
/// which the expression is false. A fully-sorted range meets this criterion.
template <typename ForwardIt, typename T, typename Compare>
[[nodiscard]] constexpr auto upper_bound(ForwardIt first, ForwardIt last, T const& value, Compare comp) -> ForwardIt
{
    using diff_t = typename iterator_traits<ForwardIt>::difference_type;

    ForwardIt it {};
    diff_t count {};
    diff_t step {};
    count = distance(first, last);

    while (count > 0) {
        it   = first;
        step = count / 2;
        advance(it, step);
        if (!comp(value, *it)) {
            first = ++it;
            count -= step + 1;
        } else {
            count = step;
        }
    }

    return first;
}

template <typename ForwardIt, typename T>
[[nodiscard]] constexpr auto upper_bound(ForwardIt first, ForwardIt last, T const& value) -> ForwardIt
{
    return upper_bound(first, last, value, less<> {});
}

} // namespace etl

#endif // TETL_ALGORITHM_UPPER_BOUND_HPP
