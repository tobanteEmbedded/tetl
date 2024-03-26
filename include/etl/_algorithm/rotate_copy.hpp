// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_ROTATE_COPY_HPP
#define TETL_ALGORITHM_ROTATE_COPY_HPP

#include "etl/_algorithm/copy.hpp"

namespace etl {

/// \brief Copies the elements from the range `[first, last)`, to another range
/// beginning at destination in such a way, that the element `nFirst` becomes
/// the first element of the new range and `nFirst - 1` becomes the last
/// element.
template <typename ForwardIt, typename OutputIt>
constexpr auto rotate_copy(ForwardIt first, ForwardIt nFirst, ForwardIt last, OutputIt destination) -> OutputIt
{
    destination = etl::copy(nFirst, last, destination);
    return etl::copy(first, nFirst, destination);
}

} // namespace etl

#endif // TETL_ALGORITHM_ROTATE_COPY_HPP
