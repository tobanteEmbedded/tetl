/*################################################################################
  ##
  ##   Copyright (C) 2016-2020 Keith O'Hara
  ##
  ##   This file is part of the GCE-Math C++ library.
  ##
  ##   Licensed under the Apache License, Version 2.0 (the "License");
  ##   you may not use this file except in compliance with the License.
  ##   You may obtain a copy of the License at
  ##
  ##       http://www.apache.org/licenses/LICENSE-2.0
  ##
  ##   Unless required by applicable law or agreed to in writing, software
  ##   distributed under the License is distributed on an "AS IS" BASIS,
  ##   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  ##   See the License for the specific language governing permissions and
  ##   limitations under the License.
  ##
  ################################################################################*/

/*
 * inverse of the incomplete gamma function
 */

#ifndef GCEM_incomplete_gamma_inv_HPP
#define GCEM_incomplete_gamma_inv_HPP

namespace internal {

template <typename T>
constexpr auto incomplete_gamma_inv_decision(T value, T a, T p, T direc, T lgVal, int iterCount) noexcept -> T;

//
// initial value for Halley

template <typename T>
constexpr auto incomplete_gamma_inv_t_val_1(const T p) noexcept -> T
{ // a > 1.0
    return (p > T(0.5) ? sqrt(-2 * log(T(1) - p)) : sqrt(-2 * log(p)));
}

template <typename T>
constexpr auto incomplete_gamma_inv_t_val_2(const T a) noexcept -> T
{ // a <= 1.0
    return (T(1) - T(0.253) * a - T(0.12) * a * a);
}

//

template <typename T>
constexpr auto incomplete_gamma_inv_initial_val_1_int_begin(const T tVal) noexcept -> T
{ // internal for a > 1.0
    return (tVal
            - (T(2.515517L) + T(0.802853L) * tVal + T(0.010328L) * tVal * tVal)
                  / (T(1) + T(1.432788L) * tVal + T(0.189269L) * tVal * tVal + T(0.001308L) * tVal * tVal * tVal));
}

template <typename T>
constexpr auto incomplete_gamma_inv_initial_val_1_int_end(const T valueInp, const T a) noexcept -> T
{ // internal for a > 1.0
    return max(T(1E-04), a * pow(T(1) - T(1) / (9 * a) - valueInp / (3 * sqrt(a)), 3));
}

template <typename T>
constexpr auto incomplete_gamma_inv_initial_val_1(const T a, const T tVal, const T sgnTerm) noexcept -> T
{ // a > 1.0
    return incomplete_gamma_inv_initial_val_1_int_end(sgnTerm * incomplete_gamma_inv_initial_val_1_int_begin(tVal), a);
}

template <typename T>
constexpr auto incomplete_gamma_inv_initial_val_2(const T a, const T p, const T tVal) noexcept -> T
{                      // a <= 1.0
    return (p < tVal ? // if
                pow(p / tVal, T(1) / a)
                     :
                     // else
                T(1) - log(T(1) - (p - tVal) / (T(1) - tVal)));
}

// initial value

template <typename T>
constexpr auto incomplete_gamma_inv_initial_val(const T a, const T p) noexcept -> T
{
    return (a > T(1) ? // if
                incomplete_gamma_inv_initial_val_1(a, incomplete_gamma_inv_t_val_1(p), p > T(0.5) ? T(-1) : T(1))
                     :
                     // else
                incomplete_gamma_inv_initial_val_2(a, p, incomplete_gamma_inv_t_val_2(a)));
}

//
// Halley recursion

template <typename T>
constexpr auto incomplete_gamma_inv_err_val(const T value, const T a, const T p) noexcept -> T
{ // err_val = f(x)
    return (incomplete_gamma(a, value) - p);
}

template <typename T>
constexpr auto incomplete_gamma_inv_deriv_1(const T value, const T a, const T lgVal) noexcept -> T
{ // derivative of the incomplete gamma function w.r.t. x
    return (exp(-value + (a - T(1)) * log(value) - lgVal));
}

template <typename T>
constexpr auto incomplete_gamma_inv_deriv_2(const T value, const T a, const T deriv1) noexcept -> T
{ // second derivative of the incomplete gamma function w.r.t. x
    return (deriv1 * ((a - T(1)) / value - T(1)));
}

template <typename T>
constexpr auto incomplete_gamma_inv_ratio_val_1(const T value, const T a, const T p, const T deriv1) noexcept -> T
{
    return (incomplete_gamma_inv_err_val(value, a, p) / deriv1);
}

template <typename T>
constexpr auto incomplete_gamma_inv_ratio_val_2(const T value, const T a, const T deriv1) noexcept -> T
{
    return (incomplete_gamma_inv_deriv_2(value, a, deriv1) / deriv1);
}

template <typename T>
constexpr auto incomplete_gamma_inv_halley(const T ratioVal1, const T ratioVal2) noexcept -> T
{
    return (ratioVal1 / max(T(0.8), min(T(1.2), T(1) - T(0.5) * ratioVal1 * ratioVal2)));
}

template <typename T>
constexpr auto incomplete_gamma_inv_recur(
    const T value, const T a, const T p, const T deriv1, const T lgVal, const int iterCount) noexcept -> T
{
    return incomplete_gamma_inv_decision(value, a, p,
        incomplete_gamma_inv_halley(
            incomplete_gamma_inv_ratio_val_1(value, a, p, deriv1), incomplete_gamma_inv_ratio_val_2(value, a, deriv1)),
        lgVal, iterCount);
}

template <typename T>
constexpr auto incomplete_gamma_inv_decision(
    const T value, const T a, const T p, const T direc, const T lgVal, const int iterCount) noexcept -> T
{
    // return( abs(direc) > GCEM_INCML_GAMMA_INV_TOL ?
    // incomplete_gamma_inv_recur(value - direc, a, p,
    // incomplete_gamma_inv_deriv_1(value,a,lg_val), lg_val) : value - direc );
    return (iterCount <= GCEM_INCML_GAMMA_INV_MAX_ITER ? // if
                incomplete_gamma_inv_recur(
                    value - direc, a, p, incomplete_gamma_inv_deriv_1(value, a, lgVal), lgVal, iterCount + 1)
                                                       :
                                                       // else
                value - direc);
}

template <typename T>
constexpr auto incomplete_gamma_inv_begin(const T initialVal, const T a, const T p, const T lgVal) noexcept -> T
{
    return incomplete_gamma_inv_recur(initialVal, a, p, incomplete_gamma_inv_deriv_1(initialVal, a, lgVal), lgVal, 1);
}

template <typename T>
constexpr auto incomplete_gamma_inv_check(const T a, const T p) noexcept -> T
{
    return ( // NaN check
        any_nan(a, p) ? etl::numeric_limits<T>::quiet_NaN() :
                      //
            etl::numeric_limits<T>::epsilon() > p           ? T(0)
        : p > T(1)                                          ? etl::numeric_limits<T>::quiet_NaN()
        : etl::numeric_limits<T>::epsilon() > abs(T(1) - p) ? etl::numeric_limits<T>::infinity()
                                                            :
                                                            //
            etl::numeric_limits<T>::epsilon() > a ? T(0)
                                                  :
                                                  // else
            incomplete_gamma_inv_begin(incomplete_gamma_inv_initial_val(a, p), a, p, lgamma(a)));
}

template <typename T1, typename T2, typename TC = common_return_t<T1, T2>>
constexpr auto incomplete_gamma_inv_type_check(const T1 a, const T2 p) noexcept -> TC
{
    return incomplete_gamma_inv_check(static_cast<TC>(a), static_cast<TC>(p));
}

} // namespace internal

/**
 * Compile-time inverse incomplete gamma function
 *
 * @param a a real-valued, non-negative input.
 * @param p a real-valued input with values in the unit-interval.
 *
 * @return Computes the inverse incomplete gamma function, a value \f$ x \f$
 * such that \f[ f(x) := \frac{\gamma(a,x)}{\Gamma(a)} - p \f] equal to zero,
 * for a given \c p. GCE-Math finds this root using Halley's method: \f[ x_{n+1}
 * = x_n - \frac{f(x_n)/f'(x_n)}{1 - 0.5 \frac{f(x_n)}{f'(x_n)}
 * \frac{f''(x_n)}{f'(x_n)} } \f] where \f[ \frac{\partial}{\partial x}
 * \left(\frac{\gamma(a,x)}{\Gamma(a)}\right) = \frac{1}{\Gamma(a)} x^{a-1}
 * \exp(-x) \f] \f[ \frac{\partial^2}{\partial x^2}
 * \left(\frac{\gamma(a,x)}{\Gamma(a)}\right) = \frac{1}{\Gamma(a)} x^{a-1}
 * \exp(-x) \left( \frac{a-1}{x} - 1 \right) \f]
 */

template <typename T1, typename T2>
constexpr auto incomplete_gamma_inv(const T1 a, const T2 p) noexcept -> common_return_t<T1, T2>
{
    return internal::incomplete_gamma_inv_type_check(a, p);
}

#endif
