// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_RESET_BIT_HPP
#define TETL_BIT_RESET_BIT_HPP

#include <etl/_concepts/unsigned_integral.hpp>

namespace etl {

template <etl::unsigned_integral T>
[[nodiscard]] constexpr auto reset_bit(T val, T bit) noexcept -> T
{
    return val & (~(T(1) << bit));
}

} // namespace etl

static_assert(etl::reset_bit(0b00000001U, 0U) == 0b00000000U);
static_assert(etl::reset_bit(0b00000010U, 1U) == 0b00000000U);
static_assert(etl::reset_bit(0b00000100U, 2U) == 0b00000000U);
static_assert(etl::reset_bit(0b00000011U, 1U) == 0b00000001U);

#endif // TETL_BIT_RESET_BIT_HPP
