// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTDLIB_LDIV_HPP
#define TETL_CSTDLIB_LDIV_HPP

#include <etl/_cstdint/intmax_t.hpp>

namespace etl {

/// \brief Return type for div, ldiv, lldiv & imaxdiv.
struct ldiv_t {
    long quot;
    long rem;
};

/// \brief Computes both the quotient and the remainder of the division of the
/// numerator x by the denominator y. The quotient is the result of the
/// expression x/y. The remainder is the result of the expression x%y.
[[nodiscard]] constexpr auto div(long x, long y) noexcept -> ldiv_t { return {x / y, x % y}; }

/// \brief Computes both the quotient and the remainder of the division of the
/// numerator x by the denominator y. The quotient is the result of the
/// expression x/y. The remainder is the result of the expression x%y.
[[nodiscard]] constexpr auto ldiv(long x, long y) noexcept -> ldiv_t { return {x / y, x % y}; }

} // namespace etl

#endif // TETL_CSTDLIB_LDIV_HPP
