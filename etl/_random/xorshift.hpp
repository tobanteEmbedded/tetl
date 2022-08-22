/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_RANDOM_XORSHIFT_HPP
#define TETL_RANDOM_XORSHIFT_HPP

#include "etl/_cstdint/uint_t.hpp"
#include "etl/_limits/numeric_limits.hpp"

namespace etl {

template <typename T, typename Derived>
struct basic_rng {
    using result_type                  = T;
    static constexpr auto default_seed = result_type { 42 };

    constexpr basic_rng() = default;
    explicit constexpr basic_rng(result_type seed) noexcept : _state { seed } { }

    constexpr auto seed(result_type value = default_seed) noexcept -> void { _state = value; }
    constexpr auto discard(unsigned long long z) noexcept -> void
    {
        for (auto i { 0ULL }; i < z; ++i) { (void)self()(); }
    }

    [[nodiscard]] constexpr auto operator()() noexcept -> result_type
    {
        _state = self().eval(_state);
        return _state;
    }

    [[nodiscard]] friend constexpr auto operator==(basic_rng const& lhs, basic_rng const& rhs) noexcept -> bool
    {
        return lhs._state == rhs._state;
    }

    [[nodiscard]] friend constexpr auto operator!=(basic_rng const& lhs, basic_rng const& rhs) noexcept -> bool
    {
        return !(lhs == rhs);
    }

private:
    auto self() -> Derived& { return static_cast<Derived&>(*this); }
    auto self() const -> Derived const& { return static_cast<Derived const&>(*this); }

    result_type _state { default_seed };
};

template <typename T>
struct basic_xorshift32 : basic_rng<T, basic_xorshift32<T>> {
    using result_type = T;

    using basic_rng<T, basic_xorshift32<T>>::basic_rng;

    [[nodiscard]] static constexpr auto min() noexcept -> result_type { return numeric_limits<uint32_t>::min(); }
    [[nodiscard]] static constexpr auto max() noexcept -> result_type { return numeric_limits<uint32_t>::max(); }

private:
    [[nodiscard]] constexpr auto eval(result_type state) noexcept -> result_type
    {
        state ^= state << uint32_t(13);
        state ^= state >> uint32_t(17);
        state ^= state << uint32_t(5);
        return state;
    }
};

template <typename T>
struct basic_xorshift64 : basic_rng<T, basic_xorshift64<T>> {
    using result_type = T;

    using basic_rng<T, basic_xorshift64<T>>::basic_rng;

    [[nodiscard]] static constexpr auto min() noexcept -> result_type { return numeric_limits<uint64_t>::min(); }
    [[nodiscard]] static constexpr auto max() noexcept -> result_type { return numeric_limits<uint64_t>::max(); }

private:
    [[nodiscard]] constexpr auto eval(result_type state) noexcept -> result_type
    {
        state ^= state << uint64_t(13);
        state ^= state >> uint64_t(7);
        state ^= state << uint64_t(17);
        return state;
    }
};

struct xorshift32 : basic_xorshift32<uint32_t> {
    using basic_xorshift32<uint32_t>::basic_xorshift32;
};

struct xorshift64 : basic_xorshift64<uint64_t> {
    using basic_xorshift64<uint64_t>::basic_xorshift64;
};

} // namespace etl

#endif // TETL_RANDOM_XORSHIFT_HPP
