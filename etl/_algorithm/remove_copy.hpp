/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_REMOVE_COPY_HPP
#define TETL_ALGORITHM_REMOVE_COPY_HPP

namespace etl {

/// \brief Copies elements from the range [first, last), to another range
/// beginning at destination, omitting the elements which satisfy specific
/// criteria. Source and destination ranges cannot overlap. Ignores all elements
/// that are equal to value.
/// \returns Iterator to the element past the last element copied.
template <typename InputIt, typename OutputIt, typename T>
constexpr auto remove_copy(InputIt first, InputIt last, OutputIt destination, T const& value) -> OutputIt
{
    return remove_copy_if(first, last, destination, [&value](auto const& item) { return item == value; });
}

} // namespace etl

#endif // TETL_ALGORITHM_REMOVE_COPY_HPP