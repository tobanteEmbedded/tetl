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
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_bswap16)
            return __builtin_bswap16(val);
#endif
        }
        return etl::detail::byteswap_fallback(val);
    }

    [[nodiscard]] constexpr auto operator()(etl::uint32_t val) const noexcept -> etl::uint32_t
    {
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_bswap32)
            return __builtin_bswap32(val);
#endif
        }
        return etl::detail::byteswap_fallback(val);
    }

    [[nodiscard]] constexpr auto operator()(etl::uint64_t val) const noexcept -> etl::uint64_t
    {
        if (not is_constant_evaluated()) {
#if __has_builtin(__builtin_bswap64)
            return __builtin_bswap64(val);
#endif
        }
        return etl::detail::byteswap_fallback(val);
    }

} byteswap;

} // namespace detail

/// \brief Reverses the bytes in the given integer value n.
///
/// \details etl::byteswap participates in overload resolution only if Int
/// satisfies integral, i.e., Int is an integer type. The program is ill-formed if
/// Int has padding bits.
///
/// https://en.cppreference.com/w/cpp/numeric/byteswap
///
/// \ingroup bit
template <integral Int>
[[nodiscard]] constexpr auto byteswap(Int val) noexcept -> Int
{
    if constexpr (sizeof(Int) == 1) {
        return val;
    } else if constexpr (sizeof(Int) == 2) {
        return static_cast<Int>(detail::byteswap(static_cast<etl::uint16_t>(val)));
    } else if constexpr (sizeof(Int) == 4) {
        return static_cast<Int>(detail::byteswap(static_cast<etl::uint32_t>(val)));
    } else if constexpr (sizeof(Int) == 8) {
        return static_cast<Int>(detail::byteswap(static_cast<etl::uint64_t>(val)));
    } else {
        static_assert(always_false<Int>, "byteswap requires sizeof(Int) <= 8");
    }
}

} // namespace etl

#endif // TETL_BIT_BYTESWAP_HPP
