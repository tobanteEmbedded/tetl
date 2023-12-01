// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RANDOM_XORSHIFT128PLUSPLUS_HPP
#define TETL_RANDOM_XORSHIFT128PLUSPLUS_HPP

#include "etl/_algorithm/equal.hpp"
#include "etl/_bit/rotl.hpp"
#include "etl/_cstdint/uint_t.hpp"
#include "etl/_iterator/begin.hpp"
#include "etl/_iterator/end.hpp"
#include "etl/_limits/numeric_limits.hpp"

namespace etl {

struct xoshiro128plusplus {
    using result_type                  = uint32_t;
    static constexpr auto default_seed = result_type { 5489U };

    constexpr xoshiro128plusplus() = default;
    explicit constexpr xoshiro128plusplus(result_type seed) noexcept : state_ { seed } { }

    [[nodiscard]] static constexpr auto min() noexcept -> result_type { return numeric_limits<uint32_t>::min(); }
    [[nodiscard]] static constexpr auto max() noexcept -> result_type { return numeric_limits<uint32_t>::max() - 1; }

    constexpr auto seed(result_type value = default_seed) noexcept -> void { state_[0] = value; }

    constexpr auto discard(unsigned long long z) noexcept -> void
    {
        for (auto i { 0ULL }; i < z; ++i) { (void)(*this)(); }
    }

    [[nodiscard]] constexpr auto operator()() noexcept -> result_type
    {
        const uint32_t result = rotl(state_[0] + state_[3], 7) + state_[0];
        const uint32_t t      = state_[1] << 9;

        state_[2] ^= state_[0];
        state_[3] ^= state_[1];
        state_[1] ^= state_[2];
        state_[0] ^= state_[3];

        state_[2] ^= t;

        state_[3] = rotl(state_[3], 11);

        return result;
    }

    [[nodiscard]] friend constexpr auto operator==(
        xoshiro128plusplus const& lhs, xoshiro128plusplus const& rhs) noexcept -> bool
    {
        return equal(begin(lhs.state_), end(lhs.state_), begin(rhs.state_), end(rhs.state_));
    }

    [[nodiscard]] friend constexpr auto operator!=(
        xoshiro128plusplus const& lhs, xoshiro128plusplus const& rhs) noexcept -> bool
    {
        return !(lhs == rhs);
    }

private:
    uint32_t state_[4] { default_seed };
};

} // namespace etl

#endif // TETL_RANDOM_XORSHIFT128PLUSPLUS_HPP
