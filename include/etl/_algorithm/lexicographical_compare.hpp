// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_ALGORITHM_LEXICOGRAPHICAL_COMPARE_HPP
#define TETL_ALGORITHM_LEXICOGRAPHICAL_COMPARE_HPP

#include <etl/_functional/less.hpp>

namespace etl {

/// \brief Checks if the first range `[f1, l1)` is lexicographically
/// less than the second range `[f2, l2)`.
///
/// https://en.cppreference.com/w/cpp/algorithm/lexicographical_compare
///
/// \ingroup algorithm
template <typename InputIt1, typename InputIt2, typename Compare>
[[nodiscard]] constexpr auto lexicographical_compare(InputIt1 f1, InputIt1 l1, InputIt2 f2, InputIt2 l2, Compare comp)
    -> bool
{
    for (; (f1 != l1) and (f2 != l2); ++f1, (void)++f2) {
        if (comp(*f1, *f2)) {
            return true;
        }
        if (comp(*f2, *f1)) {
            return false;
        }
    }
    return (f1 == l1) and (f2 != l2);
}

/// \ingroup algorithm
template <typename InputIt1, typename InputIt2>
[[nodiscard]] constexpr auto lexicographical_compare(InputIt1 f1, InputIt1 l1, InputIt2 f2, InputIt2 l2) -> bool
{
    return etl::lexicographical_compare(f1, l1, f2, l2, etl::less());
}

} // namespace etl

#endif // TETL_ALGORITHM_LEXICOGRAPHICAL_COMPARE_HPP
