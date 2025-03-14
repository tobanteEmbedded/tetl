// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RANDOM_XORSHIFT128PLUS_HPP
#define TETL_RANDOM_XORSHIFT128PLUS_HPP

#include <etl/_algorithm/equal.hpp>
#include <etl/_bit/rotl.hpp>
#include <etl/_cstdint/uint_t.hpp>
#include <etl/_iterator/begin.hpp>
#include <etl/_iterator/end.hpp>
#include <etl/_limits/numeric_limits.hpp>

namespace etl {

/// \note Non-standard extension
/// \ingroup random
struct xoshiro128plus {
    using result_type                  = uint32_t;
    static constexpr auto default_seed = result_type{5489U};

    constexpr xoshiro128plus() = default;

    explicit constexpr xoshiro128plus(result_type seed) noexcept
        : _state{seed}
    {
    }

    [[nodiscard]] static constexpr auto min() noexcept -> result_type { return numeric_limits<uint32_t>::min(); }

    [[nodiscard]] static constexpr auto max() noexcept -> result_type { return numeric_limits<uint32_t>::max() - 1; }

    constexpr auto seed(result_type value = default_seed) noexcept -> void { _state[0] = value; }

    constexpr auto discard(unsigned long long z) noexcept -> void
    {
        for (auto i{0ULL}; i < z; ++i) {
            (void)(*this)();
        }
    }

    [[nodiscard]] constexpr auto operator()() noexcept -> result_type
    {
        uint32_t const result = _state[0] + _state[3];
        uint32_t const t      = _state[1] << 9;

        _state[2] ^= _state[0];
        _state[3] ^= _state[1];
        _state[1] ^= _state[2];
        _state[0] ^= _state[3];

        _state[2] ^= t;
        _state[3] = rotl(_state[3], 11);

        return result;
    }

    [[nodiscard]] friend constexpr auto operator==(xoshiro128plus const& lhs, xoshiro128plus const& rhs) noexcept
        -> bool
    {
        return equal(begin(lhs._state), end(lhs._state), begin(rhs._state), end(rhs._state));
    }

private:
    uint32_t _state[4]{default_seed};
};

} // namespace etl

#endif // TETL_RANDOM_XORSHIFT128PLUS_HPP
