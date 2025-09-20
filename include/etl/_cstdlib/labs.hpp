// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_CSTDLIB_LABS_HPP
#define TETL_CSTDLIB_LABS_HPP

#include <etl/_math/abs.hpp>

namespace etl {

/// \brief Computes the absolute value of an integer number. The behavior is
/// undefined if the result cannot be represented by the return type. If abs
/// is called with an unsigned integral argument that cannot be converted to int
/// by integral promotion, the program is ill-formed.
[[nodiscard]] constexpr auto labs(long n) noexcept -> long
{
    return etl::detail::abs(n);
}

} // namespace etl

#endif // TETL_CSTDLIB_LABS_HPP
