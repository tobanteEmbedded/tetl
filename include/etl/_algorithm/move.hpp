// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#ifndef TETL_ALGORITHM_MOVE_HPP
#define TETL_ALGORITHM_MOVE_HPP

#include <etl/_utility/move.hpp>

namespace etl {

/// Moves the elements in the range `[first, last)`, to another range
/// beginning at destination, starting from first and proceeding to `last - 1`.
/// After this operation the elements in the moved-from range will still contain
/// valid values of the appropriate type, but not necessarily the same values as
/// before the move.
///
/// https://en.cppreference.com/w/cpp/algorithm/move
///
/// \returns Output iterator to the element past the last element moved.
///
/// \param first The range of elements to move.
/// \param last The range of elements to move.
/// \param destination The beginning of the destination range.
///
/// \ingroup algorithm
template <typename InputIt, typename OutputIt>
constexpr auto move(InputIt first, InputIt last, OutputIt destination) -> OutputIt
{
    for (; first != last; ++first, (void)++destination) {
        *destination = etl::move(*first);
    }
    return destination;
}

} // namespace etl

#endif // TETL_ALGORITHM_MOVE_HPP
