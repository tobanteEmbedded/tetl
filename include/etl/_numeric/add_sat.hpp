// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_NUMERIC_ADD_SAT_HPP
#define TETL_NUMERIC_ADD_SAT_HPP

#include <etl/_algorithm/clamp.hpp>
#include <etl/_concepts/builtin_integer.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_cstdint/int_t.hpp>
#include <etl/_cstdint/uint_t.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_type_traits/always_false.hpp>
#include <etl/_type_traits/is_signed.hpp>
#include <etl/_type_traits/is_unsigned.hpp>

namespace etl {

namespace detail {

template <etl::builtin_integer Int>
[[nodiscard]] constexpr auto add_sat_fallback(Int x, Int y) noexcept -> Int
{
    constexpr auto min = etl::numeric_limits<Int>::min();
    constexpr auto max = etl::numeric_limits<Int>::max();

    if constexpr (sizeof(Int) < sizeof(int) and etl::same_as<decltype(x + y), int>) {
        return Int(etl::clamp(x + y, int(min), int(max)));
    } else if constexpr (sizeof(Int) < sizeof(unsigned) and etl::same_as<decltype(x + y), unsigned>) {
        return Int(etl::clamp(x + y, unsigned(min), unsigned(max)));
    } else if constexpr (sizeof(Int) == 2 and is_signed_v<Int>) {
        return Int(etl::clamp(etl::int32_t(x) + etl::int32_t(y), etl::int32_t(min), etl::int32_t(max)));
    } else if constexpr (sizeof(Int) == 2 and is_unsigned_v<Int>) {
        return Int(etl::clamp(etl::uint32_t(x) + etl::uint32_t(y), etl::uint32_t(min), etl::uint32_t(max)));
    } else if constexpr (sizeof(Int) == 4 and is_signed_v<Int>) {
        return Int(etl::clamp(etl::int64_t(x) + etl::int64_t(y), etl::int64_t(min), etl::int64_t(max)));
    } else if constexpr (sizeof(Int) == 4 and is_unsigned_v<Int>) {
        return Int(etl::clamp(etl::uint64_t(x) + etl::uint64_t(y), etl::uint64_t(min), etl::uint64_t(max)));
    } else {
        if (x >= 0) {
            if (max - x < y) {
                return max;
            }
        } else {
            if (y < min - x) {
                return min;
            }
        }
        return x + y;
    }
}

} // namespace detail

/// \ingroup numeric
template <etl::builtin_integer Int>
[[nodiscard]] constexpr auto add_sat(Int x, Int y) noexcept -> Int
{
#if defined(__GNUC__) or defined(__clang__)
    constexpr auto min = etl::numeric_limits<Int>::min();
    constexpr auto max = etl::numeric_limits<Int>::max();

    if (Int sum{0}; not __builtin_add_overflow(x, y, &sum)) {
        return sum;
    }
    if constexpr (is_unsigned_v<Int>) {
        return max;
    } else {
        if (x > Int(0)) {
            return max;
        }
        return min;
    }
#else
    return etl::detail::add_sat_fallback(x, y);
#endif
}

} // namespace etl

#endif // TETL_NUMERIC_ADD_SAT_HPP
