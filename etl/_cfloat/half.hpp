/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CFLOAT_HALF_HPP
#define TETL_CFLOAT_HALF_HPP

#include "etl/_bit/bit_cast.hpp"
#include "etl/_cstdint/uint_t.hpp"

namespace etl {

struct binary_t {
};
inline constexpr auto binary = binary_t {};

struct half {
    using storage_type = etl::uint16_t;

    constexpr half() = default;
    constexpr half(binary_t /*tag*/, storage_type bits);

private:
    storage_type bits_ { 0 };
};

[[nodiscard]] constexpr auto isfinite(half arg) noexcept -> bool;
[[nodiscard]] constexpr auto isinf(half arg) noexcept -> bool;
[[nodiscard]] constexpr auto isnan(half arg) noexcept -> bool;
[[nodiscard]] constexpr auto isnormal(half arg) noexcept -> bool;
[[nodiscard]] constexpr auto signbit(half arg) noexcept -> bool;

// IMPL
namespace detail {
inline constexpr etl::half::storage_type exp_mask { 0b0111'1100'0000'0000 };
inline constexpr etl::half::storage_type man_mask { 0b0000'0011'1111'1111 };
inline constexpr etl::half::storage_type inf_mask { 0b0111'1111'1111'1111 };
inline constexpr etl::half::storage_type sign_mask { 0b1000'0000'0000'0000 };
} // namespace detail

constexpr half::half(binary_t /*tag*/, half::storage_type bits) : bits_ { bits }
{
    // [tobi] This needs to be here, or clang will complain about an unused
    // member. All free functions use bit_cast to access the underlying bits of
    // the half float, so no "getter" method exists.
    (void)bits_;
}

constexpr auto isfinite(half arg) noexcept -> bool
{
    using uint_t = half::storage_type;
    return (etl::bit_cast<uint_t>(arg) & detail::exp_mask) != detail::exp_mask;
}

constexpr auto isinf(half arg) noexcept -> bool
{
    using uint_t = half::storage_type;
    return (etl::bit_cast<uint_t>(arg) & detail::inf_mask) == detail::exp_mask;
}

constexpr auto isnan(half arg) noexcept -> bool
{
    using uint_t = half::storage_type;
    return (etl::bit_cast<uint_t>(arg) & detail::inf_mask) > detail::exp_mask;
}

constexpr auto isnormal(half arg) noexcept -> bool
{
    using uint_t    = half::storage_type;
    auto const mask = detail::exp_mask;
    auto const bits = etl::bit_cast<uint_t>(arg);
    return ((bits & mask) != 0) & ((bits & mask) != mask);
}

constexpr auto signbit(half arg) noexcept -> bool
{
    using uint_t = half::storage_type;
    return (etl::bit_cast<uint_t>(arg) & detail::sign_mask) != 0;
}

} // namespace etl

#endif // TETL_CFLOAT_HALF_HPP