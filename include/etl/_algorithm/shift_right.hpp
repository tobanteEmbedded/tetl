// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_SHIFT_RIGHT_HPP
#define TETL_ALGORITHM_SHIFT_RIGHT_HPP

#include <etl/_algorithm/move.hpp>
#include <etl/_concepts/emulation.hpp>
#include <etl/_iterator/distance.hpp>
#include <etl/_iterator/iterator_traits.hpp>
#include <etl/_iterator/next.hpp>
#include <etl/_iterator/prev.hpp>

namespace etl {

/// \brief Shifts the elements in the range [first, last) by n positions.
///
/// \details Shifts the elements towards the end of the range.
/// If n <= 0 || n >= last - first, there are no effects. Otherwise, for
/// every integer i in [0, last - first - n), moves the element originally
/// at position first + i to position first + n + i.
///
/// https://en.cppreference.com/w/cpp/algorithm/shift
///
/// \note The standard specifies that this algorithm should also work with
/// legacy forward iterators. I don't know how to implement that without
/// dynamic memory, so forward iterators are not supported.
template <typename BidiIt>
constexpr auto shift_right(BidiIt first, BidiIt last, typename iterator_traits<BidiIt>::difference_type n) -> BidiIt
{
    // The standard only checks for n == 0. n < 0 would be undefined behavior.
    // This implementation does nothing if n < 0.
    if (n <= 0 or n >= etl::distance(first, last)) {
        return last;
    }

    auto dest = etl::prev(last);
    auto src  = etl::prev(dest, n);
    for (; src != first; --dest, (void)--src) {
        *dest = TETL_MOVE(*src);
    }

    // Elements outside the new range should be left in a valid but unspecified state.
    // If the value type has a default constructor we do a little cleanup.
    using value_type = typename iterator_traits<BidiIt>::value_type;
    if constexpr (is_default_constructible_v<value_type>) {
        for (; dest != first; --dest) {
            *dest = value_type{};
        }
    }

    return etl::next(first, n);
}

} // namespace etl

#endif // TETL_ALGORITHM_SHIFT_RIGHT_HPP
