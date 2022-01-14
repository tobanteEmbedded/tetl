/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

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
    destination = copy(nFirst, last, destination);
    return copy(first, nFirst, destination);
}

} // namespace etl

#endif // TETL_ALGORITHM_ROTATE_COPY_HPP