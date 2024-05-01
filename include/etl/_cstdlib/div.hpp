// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTDLIB_DIV_HPP
#define TETL_CSTDLIB_DIV_HPP

#include <etl/_cstdint/intmax_t.hpp>

namespace etl {

/// Return type for div.
struct div_t {
    int quot;
    int rem;
};

/// Return type for ldiv.
struct ldiv_t {
    long quot;
    long rem;
};

/// Return type for lldiv.
struct lldiv_t {
    long long quot;
    long long rem;
};

/// Return type for imaxdiv.
struct imaxdiv_t {
    intmax_t quot;
    intmax_t rem;
};

/// Computes both the quotient and the remainder of the division of the
/// numerator \p x by the denominator \p y. The quotient is the result of the
/// expression `x/y`. The remainder is the result of the expression `x%y`.
[[nodiscard]] constexpr auto div(int x, int y) noexcept -> div_t { return {x / y, x % y}; }

/// Computes both the quotient and the remainder of the division of the
/// numerator \p x by the denominator \p y. The quotient is the result of the
/// expression `x/y`. The remainder is the result of the expression `x%y`.
[[nodiscard]] constexpr auto div(long x, long y) noexcept -> ldiv_t { return {x / y, x % y}; }

/// Computes both the quotient and the remainder of the division of the
/// numerator \p x by the denominator \p y. The quotient is the result of the
/// expression `x/y`. The remainder is the result of the expression `x%y`.
[[nodiscard]] constexpr auto div(long long x, long long y) noexcept -> lldiv_t { return {x / y, x % y}; }

/// Computes both the quotient and the remainder of the division of the
/// numerator \p x by the denominator \p y. The quotient is the result of the
/// expression `x/y`. The remainder is the result of the expression `x%y`.
[[nodiscard]] constexpr auto ldiv(long x, long y) noexcept -> ldiv_t { return {x / y, x % y}; }

/// Computes both the quotient and the remainder of the division of the
/// numerator \p x by the denominator \p y. The quotient is the result of the
/// expression `x/y`. The remainder is the result of the expression `x%y`.
[[nodiscard]] constexpr auto lldiv(long long x, long long y) noexcept -> lldiv_t { return {x / y, x % y}; }

/// Computes both the quotient and the remainder of the division of the
/// numerator \p x by the denominator \p y. The quotient is the result of the
/// expression `x/y`. The remainder is the result of the expression `x%y`.
[[nodiscard]] constexpr auto imaxdiv(intmax_t x, intmax_t y) noexcept -> imaxdiv_t { return {x / y, x % y}; }

} // namespace etl

#endif // TETL_CSTDLIB_DIV_HPP
