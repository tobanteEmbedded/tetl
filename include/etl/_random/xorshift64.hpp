/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_RANDOM_XORSHIFT64_HPP
#define TETL_RANDOM_XORSHIFT64_HPP

#include "etl/_cstdint/uint_t.hpp"
#include "etl/_limits/numeric_limits.hpp"

namespace etl {

struct xorshift64 {
    using result_type                  = uint64_t;
    static constexpr auto default_seed = result_type { 5489U };

    constexpr xorshift64() = default;
    explicit constexpr xorshift64(result_type seed) noexcept : _state { seed } { }

    [[nodiscard]] static constexpr auto min() noexcept -> result_type { return numeric_limits<uint64_t>::min(); }
    [[nodiscard]] static constexpr auto max() noexcept -> result_type { return numeric_limits<uint64_t>::max() - 1; }

    constexpr auto seed(result_type value = default_seed) noexcept -> void { _state = value; }

    constexpr auto discard(unsigned long long z) noexcept -> void
    {
        for (auto i { 0ULL }; i < z; ++i) { (void)(*this)(); }
    }

    [[nodiscard]] constexpr auto operator()() noexcept -> result_type
    {
        auto x = _state;
        x ^= x << uint64_t(13);
        x ^= x >> uint64_t(7);
        x ^= x << uint64_t(17);
        return _state = x;
    }

    [[nodiscard]] friend constexpr auto operator==(xorshift64 const& lhs, xorshift64 const& rhs) noexcept -> bool
    {
        return lhs._state == rhs._state;
    }

    [[nodiscard]] friend constexpr auto operator!=(xorshift64 const& lhs, xorshift64 const& rhs) noexcept -> bool
    {
        return !(lhs == rhs);
    }

private:
    uint64_t _state { default_seed };
};

} // namespace etl

#endif // TETL_RANDOM_XORSHIFT_HPP
