/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTDLIB_DIV_HPP
#define TETL_CSTDLIB_DIV_HPP

#include "etl/_cstdint/intmax_t.hpp"

namespace etl {

/// \brief Return type for div, ldiv, lldiv & imaxdiv.
struct div_t {
    int quot;
    int rem;
};

/// \brief Computes both the quotient and the remainder of the division of the
/// numerator x by the denominator y. The quotient is the result of the
/// expression x/y. The remainder is the result of the expression x%y.
[[nodiscard]] constexpr auto div(int x, int y) noexcept -> div_t
{
    return { x / y, x % y };
}

} // namespace etl

#endif // TETL_CSTDLIB_DIV_HPP