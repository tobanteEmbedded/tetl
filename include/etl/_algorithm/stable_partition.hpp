// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_STABLE_PARTITION_HPP
#define TETL_ALGORITHM_STABLE_PARTITION_HPP

#include <etl/_algorithm/rotate.hpp>

namespace etl {

/// \brief  Reorders the elements in the range `[first, last)` in such a way
/// that all elements for which the predicate p returns true precede the
/// elements for which predicate p returns false. Relative order of the
/// elements is preserved.
/// \ingroup algorithm
template <typename BidirIt, typename Predicate>
constexpr auto stable_partition(BidirIt f, BidirIt l, Predicate p) -> BidirIt
{
    auto const n = l - f;
    if (n == 0) {
        return f;
    }
    if (n == 1) {
        return f + p(*f);
    }
    auto const m = f + (n / 2);
    return etl::rotate(etl::stable_partition(f, m, p), m, etl::stable_partition(m, l, p));
}

} // namespace etl

#endif // TETL_ALGORITHM_STABLE_PARTITION_HPP
