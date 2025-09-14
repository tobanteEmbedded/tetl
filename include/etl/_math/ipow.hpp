// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_MATH_IPOW_HPP
#define TETL_MATH_IPOW_HPP

#include <etl/_concepts/builtin_integer.hpp>
#include <etl/_type_traits/make_unsigned.hpp>

namespace etl {

template <builtin_integer Int>
[[nodiscard]] constexpr auto ipow(Int base, Int exponent) noexcept -> Int
{
    auto result = Int(1);
    for (auto i = Int(0); i < exponent; ++i) {
        result *= base;
    }
    return result;
}

template <builtin_integer auto Base>
[[nodiscard]] constexpr auto ipow(decltype(Base) exponent) noexcept -> decltype(Base)
{
    using Int  = decltype(Base);
    using UInt = etl::make_unsigned_t<Int>;

    if constexpr (Base == Int(2)) {
        return static_cast<Int>(UInt(1) << UInt(exponent));
    } else if constexpr (Base == Int(4)) {
        return static_cast<Int>(UInt(1) << UInt(exponent * Int(2)));
    } else if constexpr (Base == Int(8)) {
        return static_cast<Int>(UInt(1) << UInt(exponent * Int(3)));
    } else if constexpr (Base == Int(16)) {
        return static_cast<Int>(UInt(1) << UInt(exponent * Int(4)));
    } else if constexpr (Base == Int(32)) {
        return static_cast<Int>(UInt(1) << UInt(exponent * Int(5)));
    } else {
        return ipow(Base, exponent);
    }
}

} // namespace etl

#endif // TETL_MATH_IPOW_HPP
