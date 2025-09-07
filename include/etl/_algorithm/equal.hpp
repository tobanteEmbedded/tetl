// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_ALGORITHM_EQUAL_HPP
#define TETL_ALGORITHM_EQUAL_HPP

#include <etl/_functional/equal_to.hpp>
#include <etl/_iterator/distance.hpp>
#include <etl/_iterator/iterator_traits.hpp>
#include <etl/_iterator/tags.hpp>
#include <etl/_type_traits/is_base_of.hpp>

namespace etl {

/// \brief Returns true if the range `[first1, last1)` is equal to the range
/// `[first2, first2 + (last1 - first1))`, and false otherwise.
/// \ingroup algorithm
template <typename InputIt1, typename InputIt2, typename Predicate>
[[nodiscard]] constexpr auto equal(InputIt1 first1, InputIt1 last1, InputIt2 first2, Predicate p) -> bool
{
    for (; first1 != last1; ++first1, (void)++first2) {
        if (not p(*first1, *first2)) {
            return false;
        }
    }
    return true;
}

/// \ingroup algorithm
template <typename InputIt1, typename InputIt2>
[[nodiscard]] constexpr auto equal(InputIt1 first1, InputIt1 last1, InputIt2 first2) -> bool
{
    return etl::equal(first1, last1, first2, etl::equal_to());
}

/// \ingroup algorithm
template <typename InputIt1, typename InputIt2, typename Predicate>
[[nodiscard]] constexpr auto equal(InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2, Predicate p)
    -> bool
{
    using Tag       = etl::random_access_iterator_tag;
    using Category1 = typename etl::iterator_traits<InputIt1>::iterator_category;
    using Category2 = typename etl::iterator_traits<InputIt2>::iterator_category;

    if constexpr (etl::is_base_of_v<Tag, Category1> and etl::is_base_of_v<Tag, Category2>) {
        if (etl::distance(first1, last1) != etl::distance(first2, last2)) {
            return false;
        }
    }
    return etl::equal(first1, last1, first2, p);
}

/// \ingroup algorithm
template <typename InputIt1, typename InputIt2>
[[nodiscard]] constexpr auto equal(InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2) -> bool
{
    return etl::equal(first1, last1, first2, last2, etl::equal_to());
}

} // namespace etl

#endif // TETL_ALGORITHM_EQUAL_HPP
