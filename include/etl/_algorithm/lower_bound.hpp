// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_LOWER_BOUND_HPP
#define TETL_ALGORITHM_LOWER_BOUND_HPP

#include <etl/_functional/less.hpp>
#include <etl/_iterator/advance.hpp>
#include <etl/_iterator/distance.hpp>
#include <etl/_iterator/iterator_traits.hpp>

namespace etl {

/// \brief Returns an iterator pointing to the first element in the range
/// `[first, last)` that is not less than (i.e. greater or equal to) value, or
/// last if no such element is found.
///
/// https://en.cppreference.com/w/cpp/algorithm/lower_bound
///
/// \ingroup algorithm
template <typename ForwardIt, typename T, typename Compare>
[[nodiscard]] constexpr auto
lower_bound(ForwardIt first, ForwardIt last, T const& value, Compare comp) noexcept -> ForwardIt
{
    using diff_t = typename iterator_traits<ForwardIt>::difference_type;
    ForwardIt it{};
    diff_t count{};
    diff_t step{};
    count = etl::distance(first, last);

    while (count > 0) {
        it   = first;
        step = count / 2;
        etl::advance(it, step);
        if (comp(*it, value)) {
            first = ++it;
            count -= step + 1;
        } else {
            count = step;
        }
    }

    return first;
}

/// \ingroup algorithm
template <typename ForwardIt, typename T>
[[nodiscard]] constexpr auto lower_bound(ForwardIt first, ForwardIt last, T const& value) noexcept -> ForwardIt
{
    return etl::lower_bound(first, last, value, less());
}

} // namespace etl

#endif // TETL_ALGORITHM_LOWER_BOUND_HPP
