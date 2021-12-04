/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_BIT_BYTESWAP_HPP
#define TETL_BIT_BYTESWAP_HPP

#include "etl/_cstdint/uint_t.hpp"
#include "etl/_type_traits/always_false.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

namespace detail {

[[nodiscard]] constexpr auto byteswap_u16(uint16_t val) noexcept -> uint16_t
{
    return static_cast<uint16_t>((val << 8) | (val >> 8));
}

[[nodiscard]] constexpr auto byteswap_u32(uint32_t val) noexcept -> uint32_t
{
    return (val << 24) | ((val << 8) & 0x00FF'0000) | ((val >> 8) & 0x0000'FF00)
           | (val >> 24);
}

[[nodiscard]] constexpr auto byteswap_u64(uint64_t val) noexcept -> uint64_t
{
    return (val << 56) | ((val << 40) & 0x00FF'0000'0000'0000)
           | ((val << 24) & 0x0000'FF00'0000'0000)
           | ((val << 8) & 0x0000'00FF'0000'0000)
           | ((val >> 8) & 0x0000'0000'FF00'0000)
           | ((val >> 24) & 0x0000'0000'00FF'0000)
           | ((val >> 40) & 0x0000'0000'0000'FF00) | (val >> 56);
}

} // namespace detail

/// \brief Reverses the bytes in the given integer value n.
///
/// \details etl::byteswap participates in overload resolution only if T
/// satisfies integral, i.e., T is an integer type. The program is ill-formed if
/// T has padding bits.
///
/// https://en.cppreference.com/w/cpp/numeric/byteswap
template <typename T, enable_if_t<is_integral_v<T>, int> = 0>
[[nodiscard]] constexpr auto byteswap(T val) noexcept -> T
{
    if constexpr (sizeof(T) == 1) {
        return val;
    } else if constexpr (sizeof(T) == 2) {
        return static_cast<T>(detail::byteswap_u16(static_cast<uint16_t>(val)));
    } else if constexpr (sizeof(T) == 4) {
        return static_cast<T>(detail::byteswap_u32(static_cast<uint32_t>(val)));
    } else if constexpr (sizeof(T) == 8) {
        return static_cast<T>(detail::byteswap_u64(static_cast<uint64_t>(val)));
    } else {
        static_assert(always_false<T>, "byteswap requires sizeof(T) <= 8");
    }
}

} // namespace etl

#endif // TETL_BIT_BYTESWAP_HPP