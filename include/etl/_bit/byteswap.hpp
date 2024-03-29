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

inline constexpr struct byteswap_fallback {
    [[nodiscard]] constexpr auto operator()(etl::uint16_t val) const noexcept -> etl::uint16_t
    {
        return static_cast<etl::uint16_t>((val << 8) | (val >> 8));
    }

    [[nodiscard]] constexpr auto operator()(etl::uint32_t val) const noexcept -> etl::uint32_t
    {
        return (val << 24) | ((val << 8) & 0x00FF'0000) | ((val >> 8) & 0x0000'FF00) | (val >> 24);
    }

    [[nodiscard]] constexpr auto operator()(etl::uint64_t val) const noexcept -> etl::uint64_t
    {
        return (val << 56) | ((val << 40) & 0x00FF'0000'0000'0000) | ((val << 24) & 0x0000'FF00'0000'0000)
             | ((val << 8) & 0x0000'00FF'0000'0000) | ((val >> 8) & 0x0000'0000'FF00'0000)
             | ((val >> 24) & 0x0000'0000'00FF'0000) | ((val >> 40) & 0x0000'0000'0000'FF00) | (val >> 56);
    }

} byteswap_fallback;

inline constexpr struct byteswap {
    [[nodiscard]] constexpr auto operator()(etl::uint16_t val) const noexcept -> etl::uint16_t
    {
        if (is_constant_evaluated()) {
            return etl::detail::byteswap_fallback(val);
        }
#if __has_builtin(__builtin_bswap16)
        return __builtin_bswap16(val);
#else
        return etl::detail::byteswap_fallback(val);
#endif
    }

    [[nodiscard]] constexpr auto operator()(etl::uint32_t val) const noexcept -> etl::uint32_t
    {
        if (is_constant_evaluated()) {
            return etl::detail::byteswap_fallback(val);
        }
#if __has_builtin(__builtin_bswap32)
        return __builtin_bswap32(val);
#else
        return etl::detail::byteswap_fallback(val);
#endif
    }

    [[nodiscard]] constexpr auto operator()(etl::uint64_t val) const noexcept -> etl::uint64_t
    {
        if (is_constant_evaluated()) {
            return etl::detail::byteswap_fallback(val);
        }
#if __has_builtin(__builtin_bswap64)
        return __builtin_bswap64(val);
#else
        return etl::detail::byteswap_fallback(val);
#endif
    }

} byteswap;

} // namespace detail

/// \brief Reverses the bytes in the given integer value n.
///
/// \details etl::byteswap participates in overload resolution only if T
/// satisfies integral, i.e., T is an integer type. The program is ill-formed if
/// T has padding bits.
///
/// https://en.cppreference.com/w/cpp/numeric/byteswap
///
/// \ingroup bit
template <integral T>
[[nodiscard]] constexpr auto byteswap(T val) noexcept -> T
{
    if constexpr (sizeof(T) == 1) {
        return val;
    } else if constexpr (sizeof(T) == 2) {
        return static_cast<T>(etl::detail::byteswap(static_cast<etl::uint16_t>(val)));
    } else if constexpr (sizeof(T) == 4) {
        return static_cast<T>(etl::detail::byteswap(static_cast<etl::uint32_t>(val)));
    } else if constexpr (sizeof(T) == 8) {
        return static_cast<T>(etl::detail::byteswap(static_cast<etl::uint64_t>(val)));
    } else {
        static_assert(etl::always_false<T>, "byteswap requires sizeof(T) <= 8");
    }
}

} // namespace etl

#endif // TETL_BIT_BYTESWAP_HPP
