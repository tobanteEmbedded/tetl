/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_RANDOM_XORSHIFT_HPP
#define TETL_RANDOM_XORSHIFT_HPP

#include "etl/_cstdint/uint_t.hpp"
#include "etl/_limits/numeric_limits.hpp"

namespace etl {

template <typename T>
struct basic_xorshift32 {
    using result_type                  = T;
    static constexpr auto default_seed = result_type { 42 };

    constexpr basic_xorshift32() = default;
    explicit constexpr basic_xorshift32(result_type seed) noexcept : _state { seed } { }

    [[nodiscard]] static constexpr auto min() noexcept -> result_type { return numeric_limits<uint32_t>::min(); }
    [[nodiscard]] static constexpr auto max() noexcept -> result_type { return numeric_limits<uint32_t>::max(); }

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

    [[nodiscard]] friend constexpr auto operator==(basic_xorshift32 const& lhs, basic_xorshift32 const& rhs) noexcept
        -> bool
    {
        return lhs._state == rhs._state;
    }

    [[nodiscard]] friend constexpr auto operator!=(basic_xorshift32 const& lhs, basic_xorshift32 const& rhs) noexcept
        -> bool
    {
        return !(lhs == rhs);
    }

private:
    result_type _state { default_seed };
};

template <typename T>
struct basic_xorshift64 {
    using result_type                  = T;
    static constexpr auto default_seed = result_type { 42 };

    constexpr basic_xorshift64() = default;
    explicit constexpr basic_xorshift64(result_type seed) noexcept : _state { seed } { }

    [[nodiscard]] static constexpr auto min() noexcept -> result_type { return numeric_limits<uint64_t>::min(); }
    [[nodiscard]] static constexpr auto max() noexcept -> result_type { return numeric_limits<uint64_t>::max(); }

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

    [[nodiscard]] friend constexpr auto operator==(basic_xorshift64 const& lhs, basic_xorshift64 const& rhs) noexcept
        -> bool
    {
        return lhs._state == rhs._state;
    }

    [[nodiscard]] friend constexpr auto operator!=(basic_xorshift64 const& lhs, basic_xorshift64 const& rhs) noexcept
        -> bool
    {
        return !(lhs == rhs);
    }

private:
    result_type _state { default_seed };
};

struct xorshift32 : basic_xorshift32<uint32_t> {
    using basic_xorshift32<uint32_t>::basic_xorshift32;
};

struct xorshift64 : basic_xorshift64<uint64_t> {
    using basic_xorshift64<uint64_t>::basic_xorshift64;
};

} // namespace etl

#endif // TETL_RANDOM_XORSHIFT_HPP
