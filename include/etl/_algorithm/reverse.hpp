// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_REVERSE_HPP
#define TETL_ALGORITHM_REVERSE_HPP

#include <etl/_algorithm/iter_swap.hpp>
#include <etl/_iterator/iterator_traits.hpp>
#include <etl/_iterator/tags.hpp>
#include <etl/_type_traits/is_base_of.hpp>

namespace etl {

/// \brief Reverses the order of the elements in the range `[first, last)`.
/// \ingroup algorithm
template <typename BidirIt>
constexpr auto reverse(BidirIt first, BidirIt last) -> void
{
    using category = typename etl::iterator_traits<BidirIt>::iterator_category;
    if constexpr (etl::is_base_of_v<etl::random_access_iterator_tag, category>) {
        if (first == last) {
            return;
        }

        for (--last; first < last; (void)++first, --last) {
            etl::iter_swap(first, last);
        }
    } else {
        while (first != last and first != --last) {
            etl::iter_swap(first++, last);
        }
    }
}

} // namespace etl

#endif // TETL_ALGORITHM_REVERSE_HPP
