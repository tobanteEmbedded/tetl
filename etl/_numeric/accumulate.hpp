/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#ifndef TETL_NUMERIC_ACCUMULATE_HPP
#define TETL_NUMERIC_ACCUMULATE_HPP

#include "etl/_utility/move.hpp"

namespace etl {

/// \brief Computes the sum of the given value init and the elements in the
/// range `[first, last)`.
/// https://en.cppreference.com/w/cpp/algorithm/accumulate
/// \group accumulate
/// \module Algorithm
template <typename InputIt, typename Type>
[[nodiscard]] constexpr auto accumulate(
    InputIt first, InputIt last, Type init) noexcept -> Type
{
    for (; first != last; ++first) { init = move(init) + *first; }
    return init;
}

/// \group accumulate
template <typename InputIt, typename Type, typename BinaryOperation>
[[nodiscard]] constexpr auto accumulate(
    InputIt first, InputIt last, Type init, BinaryOperation op) noexcept -> Type
{
    for (; first != last; ++first) { init = op(move(init), *first); }
    return init;
}

} // namespace etl

#endif // TETL_NUMERIC_ACCUMULATE_HPP