// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_ALGORITHM_MINMAX_ELEMENT_HPP
#define TETL_ALGORITHM_MINMAX_ELEMENT_HPP

#include <etl/_functional/less.hpp>
#include <etl/_iterator/iterator_traits.hpp>
#include <etl/_utility/pair.hpp>

namespace etl {

/// \brief Finds the smallest and greatest element in the range `[first, last)`.
/// \ingroup algorithm
template <typename ForwardIt, typename Compare>
[[nodiscard]] constexpr auto minmax_element(ForwardIt first, ForwardIt last, Compare comp) -> pair<ForwardIt, ForwardIt>
{
    auto min = first;
    auto max = first;

    if (first == last or ++first == last) {
        return {min, max};
    }

    if (comp(*first, *min)) {
        min = first;
    } else {
        max = first;
    }

    while (++first != last) {
        auto i = first;
        if (++first == last) {
            if (comp(*i, *min)) {
                min = i;
            } else if (not comp(*i, *max)) {
                max = i;
            }
            break;
        }

        if (comp(*first, *i)) {
            if (comp(*first, *min)) {
                min = first;
            }
            if (not comp(*i, *max)) {
                max = i;
            }
        } else {
            if (comp(*i, *min)) {
                min = i;
            }
            if (not comp(*first, *max)) {
                max = first;
            }
        }
    }

    return {min, max};
}

/// \brief Finds the smallest and greatest element in the range `[first, last)`.
/// \ingroup algorithm
template <typename ForwardIt>
[[nodiscard]] constexpr auto minmax_element(ForwardIt first, ForwardIt last) -> pair<ForwardIt, ForwardIt>
{
    return etl::minmax_element(first, last, etl::less());
}

} // namespace etl

#endif // TETL_ALGORITHM_MINMAX_ELEMENT_HPP
