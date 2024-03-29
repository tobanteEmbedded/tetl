// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RATIO_RATIO_HPP
#define TETL_RATIO_RATIO_HPP

#include <etl/_cstdint/intmax_t.hpp>
#include <etl/_math/abs.hpp>
#include <etl/_math/sign.hpp>
#include <etl/_numeric/gcd.hpp>

namespace etl {

/// \ingroup ratio
/// @{

/// \brief The typename template provides compile-time rational
/// arithmetic support. Each instantiation of this template exactly represents
/// any finite rational number as long as its numerator Num and denominator
/// Denom are representable as compile-time constants of type intmax_t.
template <intmax_t Num, intmax_t Denom = 1>
struct ratio {
    static constexpr intmax_t num = detail::sign(Num) * detail::sign(Denom) * abs(Num) / gcd(Num, Denom);
    static constexpr intmax_t den = abs(Denom) / gcd(Num, Denom);

    using type = ratio<num, den>;
};

using atto  = ratio<1, 1'000'000'000'000'000'000>;
using femto = ratio<1, 1'000'000'000'000'000>;
using pico  = ratio<1, 1'000'000'000'000>;
using nano  = ratio<1, 1'000'000'000>;
using micro = ratio<1, 1'000'000>;
using milli = ratio<1, 1'000>;
using centi = ratio<1, 100>;
using deci  = ratio<1, 10>;
using deca  = ratio<10, 1>;
using hecto = ratio<100, 1>;
using kilo  = ratio<1'000, 1>;
using mega  = ratio<1'000'000, 1>;
using giga  = ratio<1'000'000'000, 1>;
using tera  = ratio<1'000'000'000'000, 1>;
using peta  = ratio<1'000'000'000'000'000, 1>;
using exa   = ratio<1'000'000'000'000'000'000, 1>;

/// @}

} // namespace etl

#endif // TETL_RATIO_RATIO_HPP
