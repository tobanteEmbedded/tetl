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

template <unsigned long long Base, builtin_integer Int>
[[nodiscard]] constexpr auto ipow(Int exponent) noexcept -> Int
{
    using UInt = etl::make_unsigned_t<Int>;

    if constexpr (Base == 2ULL) {
        return static_cast<Int>(UInt(1) << UInt(exponent));
    } else if constexpr (Base == 4ULL) {
        return static_cast<Int>(UInt(1) << UInt(exponent * Int(2)));
    } else if constexpr (Base == 8ULL) {
        return static_cast<Int>(UInt(1) << UInt(exponent * Int(3)));
    } else if constexpr (Base == 16ULL) {
        return static_cast<Int>(UInt(1) << UInt(exponent * Int(4)));
    } else if constexpr (Base == 32ULL) {
        return static_cast<Int>(UInt(1) << UInt(exponent * Int(5)));
    } else {
        return etl::ipow(static_cast<Int>(Base), exponent);
    }
}

} // namespace etl

#endif // TETL_MATH_IPOW_HPP
