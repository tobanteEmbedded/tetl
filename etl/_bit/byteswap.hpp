/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_BIT_BYTESWAP_HPP
#define TETL_BIT_BYTESWAP_HPP

#include "etl/_cstdint/uint_t.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

/// \brief Reverses the bytes in the given integer value n.
///
/// \details etl::byteswap participates in overload resolution only if T
/// satisfies integral, i.e., T is an integer type. The program is ill-formed if
/// T has padding bits.
///
/// https://en.cppreference.com/w/cpp/numeric/byteswap
template <typename T>
[[nodiscard]] constexpr auto byteswap(T n) noexcept
    -> enable_if_t<is_integral_v<T>, T>
{
    static_assert(sizeof(T) <= 4);

    if constexpr (sizeof(T) == 1) { return n; }

    if constexpr (sizeof(T) == 2) {
        return uint16_t(n << uint16_t(8)) | uint16_t(n >> uint16_t(8));
    }

    if constexpr (sizeof(T) == 4) {
        auto const a = n << 24;
        auto const b = (n & 0x0000FF00) << 8;
        auto const c = (n & 0x00FF0000) >> 8;
        auto const d = n >> 24;

        return a | b | c | d;
    }

    return n;
}

} // namespace etl

#endif // TETL_BIT_BYTESWAP_HPP