/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_PARTITION_POINT_HPP
#define TETL_ALGORITHM_PARTITION_POINT_HPP

namespace etl {

/// \brief Examines the partitioned (as if by partition) range [first,
/// last) and locates the end of the first partition, that is, the first
/// element that does not satisfy p or last if all elements satisfy p.
template <typename ForwardIt, typename Predicate>
[[nodiscard]] constexpr auto partition_point(ForwardIt first, ForwardIt last, Predicate p) -> ForwardIt
{
    for (; first != last; ++first) {
        if (!p(*first)) { break; }
    }

    return first;
}

} // namespace etl

#endif // TETL_ALGORITHM_PARTITION_POINT_HPP
