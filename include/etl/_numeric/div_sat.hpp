// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_NUMERIC_DIV_SAT_HPP
#define TETL_NUMERIC_DIV_SAT_HPP

#include <etl/_concepts/builtin_integer.hpp>
#include <etl/_contracts/check.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_type_traits/is_signed.hpp>

namespace etl {

/// Computes the saturating division x / y.
/// \ingroup numeric
template <builtin_integer Int>
[[nodiscard]] constexpr auto div_sat(Int x, Int y) noexcept -> Int
{
    TETL_PRECONDITION(y != 0);
    if constexpr (etl::is_signed_v<Int>) {
        if (x == etl::numeric_limits<Int>::min() and y == Int(-1)) {
            return etl::numeric_limits<Int>::max();
        }
    }
    return x / y;
}

} // namespace etl

#endif // TETL_NUMERIC_DIV_SAT_HPP
