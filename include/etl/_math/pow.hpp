// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MATH_POW_HPP
#define TETL_MATH_POW_HPP

namespace etl::detail {

template <typename Int>
[[nodiscard]] constexpr auto is_power2_or_zero(Int value) noexcept -> bool
{
    return (value & (value - 1U)) == 0;
}

template <typename Int>
[[nodiscard]] constexpr auto is_power2(Int value) noexcept -> bool
{
    return value && is_power2_or_zero(value);
}

} // namespace etl::detail

#endif // TETL_MATH_POW_HPP
