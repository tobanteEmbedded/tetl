// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_REMOVE_COPY_HPP
#define TETL_ALGORITHM_REMOVE_COPY_HPP

#include <etl/_algorithm/remove_copy_if.hpp>

namespace etl {

/// \brief Copies elements from the range [first, last), to another range
/// beginning at destination, omitting the elements which satisfy specific
/// criteria. Source and destination ranges cannot overlap. Ignores all elements
/// that are equal to value.
/// \returns Iterator to the element past the last element copied.
/// \ingroup algorithm
template <typename InputIt, typename OutputIt, typename T>
constexpr auto remove_copy(InputIt first, InputIt last, OutputIt destination, T const& value) -> OutputIt
{
    return etl::remove_copy_if(first, last, destination, [&value](auto const& item) { return item == value; });
}

} // namespace etl

#endif // TETL_ALGORITHM_REMOVE_COPY_HPP
