// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch
#ifndef TETL_NUMERIC_ADJACENT_DIFFERENCE_HPP
#define TETL_NUMERIC_ADJACENT_DIFFERENCE_HPP

#include <etl/_functional/minus.hpp>
#include <etl/_iterator/iterator_traits.hpp>
#include <etl/_utility/move.hpp>

namespace etl {

/// \brief Computes the differences between the second and the first of each
/// adjacent pair of elements of the range [first, last) and writes them to the
/// range beginning at destination + 1. An unmodified copy of *first is written
/// to *destination.
/// \ingroup numeric
template <typename InputIt, typename OutputIt, typename BinaryOperation>
constexpr auto adjacent_difference(InputIt first, InputIt last, OutputIt destination, BinaryOperation op) -> OutputIt
{
    if (first == last) {
        return destination;
    }

    auto acc     = *first;
    *destination = acc;

    while (++first != last) {
        auto val       = *first;
        *++destination = op(val, etl::move(acc));
        acc            = etl::move(val);
    }

    return ++destination;
}

/// \ingroup numeric
template <typename InputIt, typename OutputIt>
constexpr auto adjacent_difference(InputIt first, InputIt last, OutputIt destination) -> OutputIt
{
    using value_t = typename etl::iterator_traits<InputIt>::value_type;
    return etl::adjacent_difference(first, last, destination, etl::minus<value_t>());
}

} // namespace etl

#endif // TETL_NUMERIC_ADJACENT_DIFFERENCE_HPP
