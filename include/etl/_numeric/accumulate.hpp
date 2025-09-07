// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch
#ifndef TETL_NUMERIC_ACCUMULATE_HPP
#define TETL_NUMERIC_ACCUMULATE_HPP

#include <etl/_utility/move.hpp>

namespace etl {

/// \brief Computes the sum of the given value init and the elements in the range `[first, last)`.
/// \details https://en.cppreference.com/w/cpp/algorithm/accumulate
/// \ingroup numeric
template <typename InputIt, typename Type>
[[nodiscard]] constexpr auto accumulate(InputIt first, InputIt last, Type init) noexcept -> Type
{
    for (; first != last; ++first) {
        init = etl::move(init) + *first;
    }
    return init;
}

/// \brief Computes the sum of the given value init and the elements in the range `[first, last)`.
/// \details https://en.cppreference.com/w/cpp/algorithm/accumulate
/// \ingroup numeric
template <typename InputIt, typename Type, typename BinaryOperation>
[[nodiscard]] constexpr auto accumulate(InputIt first, InputIt last, Type init, BinaryOperation op) noexcept -> Type
{
    for (; first != last; ++first) {
        init = op(etl::move(init), *first);
    }
    return init;
}

} // namespace etl

#endif // TETL_NUMERIC_ACCUMULATE_HPP
