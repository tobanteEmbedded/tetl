// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_BYTESWAP_HPP
#define TETL_BIT_BYTESWAP_HPP

#include <etl/_concepts/unsigned_integral.hpp>
#include <etl/_config/all.hpp>
#include <etl/_cstdint/uint_t.hpp>
#include <etl/_type_traits/always_false.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

namespace etl {

namespace detail {

[[nodiscard]] constexpr auto byteswap_u16_fallback(uint16_t val) noexcept -> uint16_t
{
    return static_cast<uint16_t>((val << 8) | (val >> 8));
}

[[nodiscard]] constexpr auto byteswap_u32_fallback(uint32_t val) noexcept -> uint32_t
{
    return (val << 24) | ((val << 8) & 0x00FF'0000) | ((val >> 8) & 0x0000'FF00) | (val >> 24);
}

[[nodiscard]] constexpr auto byteswap_u64_fallback(uint64_t val) noexcept -> uint64_t
{
    return (val << 56) | ((val << 40) & 0x00FF'0000'0000'0000) | ((val << 24) & 0x0000'FF00'0000'0000)
         | ((val << 8) & 0x0000'00FF'0000'0000) | ((val >> 8) & 0x0000'0000'FF00'0000)
         | ((val >> 24) & 0x0000'0000'00FF'0000) | ((val >> 40) & 0x0000'0000'0000'FF00) | (val >> 56);
}

[[nodiscard]] constexpr auto byteswap_u16(uint16_t val) noexcept -> uint16_t
{
    if (is_constant_evaluated()) {
        return byteswap_u16_fallback(val);
    }
#if __has_builtin(__builtin_bswap16)
    return __builtin_bswap16(val);
#else
    return byteswap_u16_fallback(val);
#endif
}

[[nodiscard]] constexpr auto byteswap_u32(uint32_t val) noexcept -> uint32_t
{
    if (is_constant_evaluated()) {
        return byteswap_u32_fallback(val);
    }
#if __has_builtin(__builtin_bswap32)
    return __builtin_bswap32(val);
#else
    return byteswap_u32_fallback(val);
#endif
}

[[nodiscard]] constexpr auto byteswap_u64(uint64_t val) noexcept -> uint64_t
{
    if (is_constant_evaluated()) {
        return byteswap_u64_fallback(val);
    }
#if __has_builtin(__builtin_bswap64)
    return __builtin_bswap64(val);
#else
    return byteswap_u64_fallback(val);
#endif
}

} // namespace detail

/// \brief Reverses the bytes in the given integer value n.
///
/// \details etl::byteswap participates in overload resolution only if T
/// satisfies integral, i.e., T is an integer type. The program is ill-formed if
/// T has padding bits.
///
/// https://en.cppreference.com/w/cpp/numeric/byteswap
template <integral T>
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
