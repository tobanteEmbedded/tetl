/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_BIT_SET_BIT_HPP
#define TETL_BIT_SET_BIT_HPP

#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_unsigned.hpp"

namespace etl {

template <typename T, enable_if_t<is_unsigned_v<T>, int> = 0>
[[nodiscard]] constexpr auto set_bit(T val, T bit) noexcept -> T
{
    return val | (T { 1 } << bit);
}

} // namespace etl

static_assert(etl::set_bit(0b00000000U, 0U) == 0b00000001U);
static_assert(etl::set_bit(0b00000000U, 1U) == 0b00000010U);
static_assert(etl::set_bit(0b00000000U, 2U) == 0b00000100U);

#endif // TETL_BIT_SET_BIT_HPP