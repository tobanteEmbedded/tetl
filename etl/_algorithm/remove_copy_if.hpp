/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_ALGORITHM_REMOVE_COPY_IF_HPP
#define TETL_ALGORITHM_REMOVE_COPY_IF_HPP

namespace etl {

/// \brief Copies elements from the range [first, last), to another range
/// beginning at destination, omitting the elements which satisfy specific
/// criteria. Source and destination ranges cannot overlap. Ignores all elements
/// for which predicate p returns true.
/// \returns Iterator to the element past the last element copied.
template <typename InputIt, typename OutputIt, typename Predicate>
constexpr auto remove_copy_if(InputIt first, InputIt last, OutputIt destination, Predicate p) -> OutputIt
{
    for (; first != last; ++first, (void)++destination) {
        if (!p(*first)) { *destination = *first; }
    }

    return destination;
}

} // namespace etl

#endif // TETL_ALGORITHM_REMOVE_COPY_IF_HPP