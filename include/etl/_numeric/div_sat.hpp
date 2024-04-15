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
template <builtin_integer T>
[[nodiscard]] constexpr auto div_sat(T x, T y) noexcept -> T
{
    TETL_PRECONDITION(y != 0);
    if constexpr (etl::is_signed_v<T>) {
        if (x == etl::numeric_limits<T>::min() and y == T(-1)) {
            return etl::numeric_limits<T>::max();
        }
    }
    return x / y;
}

} // namespace etl

#endif // TETL_NUMERIC_DIV_SAT_HPP
