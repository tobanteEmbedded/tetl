// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MATH_IDIV_HPP
#define TETL_MATH_IDIV_HPP

#include <etl/_concepts/integral.hpp>

namespace etl {

template <integral Int>
struct idiv_result {
    Int quot;
    Int rem;
};

template <integral Int>
[[nodiscard]] constexpr auto idiv(Int x, Int y) noexcept -> idiv_result<Int>
{
    return {static_cast<Int>(x / y), static_cast<Int>(x % y)};
}

} // namespace etl

#endif // TETL_MATH_IDIV_HPP
