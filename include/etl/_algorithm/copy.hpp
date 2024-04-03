// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_COPY_HPP
#define TETL_ALGORITHM_COPY_HPP

namespace etl {

/// \brief Copies the elements in the range, defined by `[first, last)`, to
/// another range beginning at destination.
/// \details Copies all elements in the range `[first, last)` starting from
/// first and proceeding to `last - 1`. The behavior is undefined if destination
/// is within the range `[first, last)`. In this case, copy_backward may be used
/// instead.
/// \returns Output iterator to the element in the destination range, one past
/// the last element copied.
/// \ingroup algorithm
template <typename InputIt, typename OutputIt>
constexpr auto copy(InputIt first, InputIt last, OutputIt destination) -> OutputIt
{
    for (; first != last; ++first, (void)++destination) {
        *destination = *first;
    }
    return destination;
}

} // namespace etl

#endif // TETL_ALGORITHM_COPY_HPP
