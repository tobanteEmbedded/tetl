// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#ifndef TETL_CSTDINT_UINT128_HPP
#define TETL_CSTDINT_UINT128_HPP

#include <etl/_config/all.hpp>

#include <etl/_cstdint/uint_t.hpp>
#include <etl/_limits/numeric_limits.hpp>

namespace etl {

struct uint128 {
    constexpr uint128() = default;

    constexpr uint128(uint64_t val) noexcept
        : _low{val}
    {
    }

    constexpr uint128(uint64_t high, uint64_t low) noexcept
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        : _low{low}
        , _high{high}
#else
        : _high{high}
        , _low{low}
#endif
    {
    }

    [[nodiscard]] constexpr explicit operator bool() const noexcept
    {
        return (low() | high()) != 0;
    }

    [[nodiscard]] constexpr explicit operator uint64_t() const noexcept
    {
        return low();
    }

    [[nodiscard]] constexpr auto low() const noexcept -> uint64_t
    {
        return _low;
    }

    [[nodiscard]] constexpr auto high() const noexcept -> uint64_t
    {
        return _high;
    }

    friend constexpr auto operator==(uint128 const& lhs, uint128 const& rhs) noexcept -> bool
    {
        return (lhs.low() == rhs.low()) and (lhs.high() == rhs.high());
    }

    friend constexpr auto operator!=(uint128 const& lhs, uint128 const& rhs) noexcept -> bool
    {
        return not(lhs == rhs);
    }

    friend constexpr auto operator<(uint128 const& a, uint128 const& b) noexcept -> bool
    {
        return (a.high() < b.high()) or (a.high() == b.high() and a.low() < b.low());
    }

    friend constexpr auto operator>(uint128 const& a, uint128 const& b) noexcept -> bool
    {
        return b < a;
    }

    friend constexpr auto operator<=(uint128 const& a, uint128 const& b) noexcept -> bool
    {
        return not(b < a);
    }

    friend constexpr auto operator>=(uint128 const& a, uint128 const& b) noexcept -> bool
    {
        return not(a < b);
    }

    friend constexpr auto operator&(uint128 const& lhs, uint128 const& rhs) noexcept -> uint128
    {
        return {lhs.low() & rhs.low(), lhs.high() & rhs.high()};
    }

    friend constexpr auto operator|(uint128 const& lhs, uint128 const& rhs) noexcept -> uint128
    {
        return {lhs.low() | rhs.low(), lhs.high() | rhs.high()};
    }

    friend constexpr auto operator^(uint128 const& lhs, uint128 const& rhs) noexcept -> uint128
    {
        return {lhs.low() ^ rhs.low(), lhs.high() ^ rhs.high()};
    }

    friend constexpr auto operator+(uint128 const& a, uint128 const& b) noexcept -> uint128
    {
        auto const [low, carry] = add_with_carry(a.low(), b.low());
        return {a.high() + b.high() + carry, low};
    }

private:
    struct with_carry {
        uint64_t val;
        uint64_t carry;
    };

    static constexpr auto add_with_carry(uint64_t a, uint64_t b) noexcept -> with_carry
    {
        auto s = a + b;
        return with_carry{s, static_cast<uint64_t>(s < a)};
    }

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint64_t _low{0};
    uint64_t _high{0};
#else
    uint64_t _high{0};
    uint64_t _low{0};
#endif
};

using uint128_t = uint128;

template <>
struct numeric_limits<uint128> {
    static constexpr bool is_specialized = true;

    static constexpr auto lowest() noexcept -> uint128
    {
        return uint128{0};
    }
    static constexpr auto min() noexcept -> uint128
    {
        return uint128{0};
    }
    static constexpr auto max() noexcept -> uint128
    {
        return uint128{~uint64_t{0}, ~uint64_t{0}};
    }
};

}; // namespace etl

#endif // TETL_CSTDINT_UINT128_HPP
