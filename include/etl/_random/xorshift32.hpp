/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_RANDOM_XORSHIFT32_HPP
#define TETL_RANDOM_XORSHIFT32_HPP

#include "etl/_cstdint/uint_t.hpp"
#include "etl/_limits/numeric_limits.hpp"

namespace etl {

struct xorshift32 {
    using result_type                  = uint32_t;
    static constexpr auto default_seed = result_type { 5489U };

    constexpr xorshift32() = default;
    explicit constexpr xorshift32(result_type seed) noexcept : _state { seed } { }

    [[nodiscard]] static constexpr auto min() noexcept -> result_type { return numeric_limits<uint32_t>::min(); }
    [[nodiscard]] static constexpr auto max() noexcept -> result_type { return numeric_limits<uint32_t>::max() - 1; }

    constexpr auto seed(result_type value = default_seed) noexcept -> void { _state = value; }

    constexpr auto discard(unsigned long long z) noexcept -> void
    {
        for (auto i { 0ULL }; i < z; ++i) { (void)(*this)(); }
    }

    [[nodiscard]] constexpr auto operator()() noexcept -> result_type
    {
        auto x = _state;
        x ^= x << uint32_t(13);
        x ^= x >> uint32_t(17);
        x ^= x << uint32_t(5);
        return _state = x;
    }

    [[nodiscard]] friend constexpr auto operator==(xorshift32 const& lhs, xorshift32 const& rhs) noexcept -> bool
    {
        return lhs._state == rhs._state;
    }

    [[nodiscard]] friend constexpr auto operator!=(xorshift32 const& lhs, xorshift32 const& rhs) noexcept -> bool
    {
        return !(lhs == rhs);
    }

private:
    uint32_t _state { default_seed };
};

} // namespace etl

#endif // TETL_RANDOM_XORSHIFT32_HPP
