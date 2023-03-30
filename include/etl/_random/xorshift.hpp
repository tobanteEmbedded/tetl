// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RANDOM_XORSHIFT_HPP
#define TETL_RANDOM_XORSHIFT_HPP

#include "etl/_concepts/unsigned_integral.hpp"
#include "etl/_cstdint/uint_t.hpp"
#include "etl/_limits/numeric_limits.hpp"
#include "etl/_type_traits/is_same.hpp"

namespace etl {

template <unsigned_integral UInt, UInt X, UInt Y, UInt Z>
struct xorshift {
    using result_type                  = UInt;
    static constexpr auto default_seed = result_type { 5489U };

    constexpr xorshift() = default;
    explicit constexpr xorshift(result_type seed) noexcept : _state { seed } { }

    [[nodiscard]] static constexpr auto min() noexcept -> result_type { return numeric_limits<result_type>::min(); }
    [[nodiscard]] static constexpr auto max() noexcept -> result_type { return numeric_limits<result_type>::max() - 1; }

    constexpr auto seed(result_type value = default_seed) noexcept -> void { _state = value; }

    constexpr auto discard(unsigned long long z) noexcept -> void
    {
        for (auto i { 0ULL }; i < z; ++i) { (void)(*this)(); }
    }

    [[nodiscard]] constexpr auto operator()() noexcept -> result_type
    {
        auto s = _state;
        s ^= s << result_type(X);
        s ^= s >> result_type(Y);
        s ^= s << result_type(Z);
        return _state = s;
    }

    [[nodiscard]] friend constexpr auto operator==(xorshift const& lhs, xorshift const& rhs) noexcept -> bool
    {
        return lhs._state == rhs._state;
    }

    [[nodiscard]] friend constexpr auto operator!=(xorshift const& lhs, xorshift const& rhs) noexcept -> bool
    {
        return !(lhs == rhs);
    }

private:
    result_type _state { default_seed };
};

/// \brief 16-bit pseudo number generator
/// http://www.retroprogramming.com/2017/07/xorshift-pseudorandom-numbers-in-z80.html
/// https://codebase64.org/doku.php?id=base:16bit_xorshift_random_generator
using xorshift16 = xorshift<uint16_t, 7, 9, 8>;

/// \brief 32-bit pseudo number generator
/// https://en.wikipedia.org/wiki/Xorshift
using xorshift32 = xorshift<uint32_t, 13, 17, 5>;

/// \brief 64-bit pseudo number generator
/// https://en.wikipedia.org/wiki/Xorshift
using xorshift64 = xorshift<uint64_t, 13, 7, 17>;

} // namespace etl

#endif // TETL_RANDOM_XORSHIFT_HPP
