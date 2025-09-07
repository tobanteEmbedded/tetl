// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_MATH_IPOW_HPP
#define TETL_MATH_IPOW_HPP

#include <etl/_concepts/integral.hpp>

namespace etl {

template <integral Int>
[[nodiscard]] constexpr auto ipow(Int base, Int exponent) noexcept -> Int
{
    auto result = Int(1);
    for (auto i = Int(0); i < exponent; ++i) {
        result *= base;
    }
    return result;
}

template <auto Base>
[[nodiscard]] constexpr auto ipow(decltype(Base) exponent) noexcept -> decltype(Base)
{
    using Int = decltype(Base);

    if constexpr (Base == Int(2)) {
        return static_cast<Int>(Int(1) << exponent);
    } else {
        return ipow(Base, exponent);
    }
}

} // namespace etl

#endif // TETL_MATH_IPOW_HPP
