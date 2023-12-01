// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTDLIB_LLDIV_HPP
#define TETL_CSTDLIB_LLDIV_HPP

namespace etl {

/// \brief Return type for div, ldiv, lldiv & imaxdiv.
struct lldiv_t {
    long long quot;
    long long rem;
};

/// \brief Computes both the quotient and the remainder of the division of the
/// numerator x by the denominator y. The quotient is the result of the
/// expression x/y. The remainder is the result of the expression x%y.
[[nodiscard]] constexpr auto div(long long x, long long y) noexcept -> lldiv_t { return {x / y, x % y}; }

/// \brief Computes both the quotient and the remainder of the division of the
/// numerator x by the denominator y. The quotient is the result of the
/// expression x/y. The remainder is the result of the expression x%y.
[[nodiscard]] constexpr auto lldiv(long long x, long long y) noexcept -> lldiv_t { return {x / y, x % y}; }

} // namespace etl

#endif // TETL_CSTDLIB_LLDIV_HPP
