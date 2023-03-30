// SPDX-License-Identifier: BSL-1.0
#ifndef TETL_NUMERIC_PARTIAL_SUM_HPP
#define TETL_NUMERIC_PARTIAL_SUM_HPP

#include "etl/_functional/plus.hpp"
#include "etl/_utility/move.hpp"

namespace etl {

/// \brief Computes the partial sums of the elements in the subranges of the
/// range [first, last) and writes them to the range beginning at destination.
/// This version uses the given binary function op, both applying etl::move to
/// their operands on the left hand side.
///
/// \details BinaryFunction must not invalidate any iterators, including the end
/// iterators, or modify any elements of the range involved.
///
/// https://en.cppreference.com/w/cpp/algorithm/partial_sum
///
/// \returns Iterator to the element past the last element written.
template <typename InputIt, typename OutputIt, typename BinaryOperation>
constexpr auto partial_sum(InputIt first, InputIt last, OutputIt destination, BinaryOperation op) -> OutputIt
{
    if (first == last) { return destination; }

    auto sum     = *first;
    *destination = sum;

    while (++first != last) {
        sum            = op(etl::move(sum), *first);
        *++destination = sum;
    }

    return ++destination;
}

template <typename InputIt, typename OutputIt>
constexpr auto partial_sum(InputIt first, InputIt last, OutputIt destination) -> OutputIt
{
    return etl::partial_sum(first, last, destination, etl::plus<>());
}

} // namespace etl

#endif // TETL_NUMERIC_PARTIAL_SUM_HPP
