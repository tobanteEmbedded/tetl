// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_SET_BIT_HPP
#define TETL_BIT_SET_BIT_HPP

#include <etl/_concepts/unsigned_integral.hpp>

namespace etl {

template <unsigned_integral T>
[[nodiscard]] constexpr auto set_bit(T val, T bit) noexcept -> T
{
    return val | (T { 1 } << bit);
}

} // namespace etl

static_assert(etl::set_bit(0b00000000U, 0U) == 0b00000001U);
static_assert(etl::set_bit(0b00000000U, 1U) == 0b00000010U);
static_assert(etl::set_bit(0b00000000U, 2U) == 0b00000100U);

#endif // TETL_BIT_SET_BIT_HPP
