// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_MATH_ILOG2_HPP
#define TETL_MATH_ILOG2_HPP

#include <etl/_concepts/integral.hpp>

namespace etl {

template <integral Int>
[[nodiscard]] constexpr auto ilog2(Int x) noexcept -> Int
{
    auto result = Int(0);
    for (; x > Int(1); x >>= Int(1)) {
        ++result;
    }
    return result;
}

} // namespace etl

#endif // TETL_MATH_ILOG2_HPP
