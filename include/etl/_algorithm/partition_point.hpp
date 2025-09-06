// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_ALGORITHM_PARTITION_POINT_HPP
#define TETL_ALGORITHM_PARTITION_POINT_HPP

namespace etl {

/// \brief Examines the partitioned (as if by partition) range [first,
/// last) and locates the end of the first partition, that is, the first
/// element that does not satisfy p or last if all elements satisfy p.
/// \ingroup algorithm
template <typename ForwardIt, typename Predicate>
[[nodiscard]] constexpr auto partition_point(ForwardIt first, ForwardIt last, Predicate p) -> ForwardIt
{
    for (; first != last; ++first) {
        if (not p(*first)) {
            break;
        }
    }

    return first;
}

} // namespace etl

#endif // TETL_ALGORITHM_PARTITION_POINT_HPP
