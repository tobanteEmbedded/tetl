/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_EQUAL_HPP
#define TETL_ALGORITHM_EQUAL_HPP

#include "etl/_functional/equal_to.hpp"
#include "etl/_iterator/distance.hpp"

namespace etl {

/// \brief Returns true if the range `[first1, last1)` is equal to the range
/// `[first2, first2 + (last1 - first1))`, and false otherwise.
template <typename InputIt1, typename InputIt2, typename Predicate>
[[nodiscard]] constexpr auto equal(InputIt1 first1, InputIt1 last1, InputIt2 first2, Predicate p) -> bool
{
    for (; first1 != last1; ++first1, (void)++first2) {
        if (!p(*first1, *first2)) { return false; }
    }
    return true;
}

template <typename InputIt1, typename InputIt2>
[[nodiscard]] constexpr auto equal(InputIt1 first1, InputIt1 last1, InputIt2 first2) -> bool
{
    return equal(first1, last1, first2, equal_to<> {});
}

template <typename InputIt1, typename InputIt2, typename Predicate>
[[nodiscard]] constexpr auto equal(InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2, Predicate p)
    -> bool
{
    if (distance(first1, last1) != distance(first2, last2)) { return false; }
    return equal(first1, last1, first2, p);
}

template <typename InputIt1, typename InputIt2>
[[nodiscard]] constexpr auto equal(InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2) -> bool
{
    return equal(first1, last1, first2, last2, equal_to<> {});
}

} // namespace etl

#endif // TETL_ALGORITHM_EQUAL_HPP