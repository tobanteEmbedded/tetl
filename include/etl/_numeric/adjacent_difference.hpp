// SPDX-License-Identifier: BSL-1.0
#ifndef TETL_NUMERIC_ADJACENT_DIFFERENCE_HPP
#define TETL_NUMERIC_ADJACENT_DIFFERENCE_HPP

#include <etl/_iterator/iterator_traits.hpp>
#include <etl/_utility/move.hpp>

namespace etl {

/// \brief Computes the differences between the second and the first of each
/// adjacent pair of elements of the range [first, last) and writes them to the
/// range beginning at destination + 1. An unmodified copy of *first is written
/// to *destination.
template <typename InputIt, typename OutputIt, typename BinaryOperation>
constexpr auto adjacent_difference(InputIt first, InputIt last, OutputIt destination, BinaryOperation op) -> OutputIt
{
    using value_t = typename etl::iterator_traits<InputIt>::value_type;

    if (first == last) {
        return destination;
    }

    value_t acc  = *first;
    *destination = acc;

    while (++first != last) {
        value_t val    = *first;
        *++destination = op(val, TETL_MOVE(acc));
        acc            = TETL_MOVE(val);
    }

    return ++destination;
}

template <typename InputIt, typename OutputIt>
constexpr auto adjacent_difference(InputIt first, InputIt last, OutputIt destination) -> OutputIt
{
    using value_t = typename etl::iterator_traits<InputIt>::value_type;

    if (first == last) {
        return destination;
    }

    value_t acc  = *first;
    *destination = acc;

    while (++first != last) {
        value_t val    = *first;
        *++destination = val - TETL_MOVE(acc);
        acc            = TETL_MOVE(val);
    }

    return ++destination;
}

} // namespace etl

#endif // TETL_NUMERIC_ADJACENT_DIFFERENCE_HPP
