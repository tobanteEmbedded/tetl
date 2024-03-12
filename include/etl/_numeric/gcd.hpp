// SPDX-License-Identifier: BSL-1.0
#ifndef TETL_NUMERIC_GCD_HPP
#define TETL_NUMERIC_GCD_HPP

#include "etl/_type_traits/common_type.hpp"

namespace etl {

/// \brief Computes the greatest common divisor of the integers m and n.
///
/// \returns If both m and n are zero, returns zero. Otherwise, returns the
/// greatest common divisor of |m| and |n|.
template <typename M, typename N>
[[nodiscard]] constexpr auto gcd(M m, N n) noexcept -> etl::common_type_t<M, N>
{
    if (n == 0) {
        return m;
    }
    return gcd<M, N>(n, m % n);
}

} // namespace etl

#endif // TETL_NUMERIC_GCD_HPP
