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
 * inverse of the incomplete beta function
 */

#ifndef GCEM_incomplete_beta_inv_HPP
#define GCEM_incomplete_beta_inv_HPP

namespace internal {

template <typename T>
constexpr auto incomplete_beta_inv_decision(
    T value, T alphaPar, T betaPar, T p, T direc, T lbVal, int iterCount) noexcept -> T;

//
// initial value for Halley

//
// a,b > 1 case

template <typename T>
constexpr auto incomplete_beta_inv_initial_val_1_tval(const T p) noexcept -> T
{                        // a > 1.0
    return (p > T(0.5) ? // if
                sqrt(-T(2) * log(T(1) - p))
                       :
                       // else
                sqrt(-T(2) * log(p)));
}

template <typename T>
constexpr auto incomplete_beta_inv_initial_val_1_int_begin(const T tVal) noexcept -> T
{ // internal for a > 1.0
    return (tVal
            - (T(2.515517) + T(0.802853) * tVal + T(0.010328) * tVal * tVal)
                  / (T(1) + T(1.432788) * tVal + T(0.189269) * tVal * tVal + T(0.001308) * tVal * tVal * tVal));
}

template <typename T>
constexpr auto incomplete_beta_inv_initial_val_1_int_ab1(const T alphaPar, const T betaPar) noexcept -> T
{
    return (T(1) / (2 * alphaPar - T(1)) + T(1) / (2 * betaPar - T(1)));
}

template <typename T>
constexpr auto incomplete_beta_inv_initial_val_1_int_ab2(const T alphaPar, const T betaPar) noexcept -> T
{
    return (T(1) / (2 * betaPar - T(1)) - T(1) / (2 * alphaPar - T(1)));
}

template <typename T>
constexpr auto incomplete_beta_inv_initial_val_1_int_h(const T abTerm1) noexcept -> T
{
    return (T(2) / abTerm1);
}

template <typename T>
constexpr auto incomplete_beta_inv_initial_val_1_int_w(const T value, const T abTerm2, const T hTerm) noexcept -> T
{
    // return( value * sqrt(h_term + lambda)/h_term - ab_term_2*(lambda
    // + 5.0/6.0 -2.0/(3.0*h_term)) );
    return (value * sqrt(hTerm + (value * value - T(3)) / T(6)) / hTerm
            - abTerm2 * ((value * value - T(3)) / T(6) + T(5) / T(6) - T(2) / (T(3) * hTerm)));
}

template <typename T>
constexpr auto incomplete_beta_inv_initial_val_1_int_end(const T alphaPar, const T betaPar, const T wTerm) noexcept -> T
{
    return (alphaPar / (alphaPar + betaPar * exp(2 * wTerm)));
}

template <typename T>
constexpr auto incomplete_beta_inv_initial_val_1(
    const T alphaPar, const T betaPar, const T tVal, const T sgnTerm) noexcept -> T
{ // a > 1.0
    return incomplete_beta_inv_initial_val_1_int_end(alphaPar, betaPar,
        incomplete_beta_inv_initial_val_1_int_w(sgnTerm * incomplete_beta_inv_initial_val_1_int_begin(tVal),
            incomplete_beta_inv_initial_val_1_int_ab2(alphaPar, betaPar),
            incomplete_beta_inv_initial_val_1_int_h(incomplete_beta_inv_initial_val_1_int_ab1(alphaPar, betaPar))));
}

//
// a,b else

template <typename T>
constexpr auto incomplete_beta_inv_initial_val_2_s1(const T alphaPar, const T betaPar) noexcept -> T
{
    return (pow(alphaPar / (alphaPar + betaPar), alphaPar) / alphaPar);
}

template <typename T>
constexpr auto incomplete_beta_inv_initial_val_2_s2(const T alphaPar, const T betaPar) noexcept -> T
{
    return (pow(betaPar / (alphaPar + betaPar), betaPar) / betaPar);
}

template <typename T>
constexpr auto incomplete_beta_inv_initial_val_2(
    const T alphaPar, const T betaPar, const T p, const T s1, const T s2) noexcept -> T
{
    return (p <= s1 / (s1 + s2) ? pow(p * (s1 + s2) * alphaPar, T(1) / alphaPar)
                                : T(1) - pow(p * (s1 + s2) * betaPar, T(1) / betaPar));
}

// initial value

template <typename T>
constexpr auto incomplete_beta_inv_initial_val(const T alphaPar, const T betaPar, const T p) noexcept -> T
{
    return ((alphaPar > T(1) && betaPar > T(1)) ?
                                                // if
                incomplete_beta_inv_initial_val_1(
                    alphaPar, betaPar, incomplete_beta_inv_initial_val_1_tval(p), p < T(0.5) ? T(1) : T(-1))
                                                :
                                                // else
                p > T(0.5) ?
                           // if
                    T(1)
                        - incomplete_beta_inv_initial_val_2(betaPar, alphaPar, T(1) - p,
                            incomplete_beta_inv_initial_val_2_s1(betaPar, alphaPar),
                            incomplete_beta_inv_initial_val_2_s2(betaPar, alphaPar))
                           :
                           // else
                    incomplete_beta_inv_initial_val_2(alphaPar, betaPar, p,
                        incomplete_beta_inv_initial_val_2_s1(alphaPar, betaPar),
                        incomplete_beta_inv_initial_val_2_s2(alphaPar, betaPar)));
}

//
// Halley recursion

template <typename T>
constexpr auto incomplete_beta_inv_err_val(const T value, const T alphaPar, const T betaPar, const T p) noexcept -> T
{ // err_val = f(x)
    return (incomplete_beta(alphaPar, betaPar, value) - p);
}

template <typename T>
constexpr auto incomplete_beta_inv_deriv_1(const T value, const T alphaPar, const T betaPar, const T lbVal) noexcept
    -> T
{            // derivative of the incomplete beta function w.r.t. x
    return ( // indistinguishable from zero or one
        etl::numeric_limits<T>::epsilon() > abs(value)          ? T(0)
        : etl::numeric_limits<T>::epsilon() > abs(T(1) - value) ? T(0)
                                                                :
                                                                // else
            exp((alphaPar - T(1)) * log(value) + (betaPar - T(1)) * log(T(1) - value) - lbVal));
}

template <typename T>
constexpr auto incomplete_beta_inv_deriv_2(const T value, const T alphaPar, const T betaPar, const T deriv1) noexcept
    -> T
{ // second derivative of the incomplete beta function w.r.t. x
    return (deriv1 * ((alphaPar - T(1)) / value - (betaPar - T(1)) / (T(1) - value)));
}

template <typename T>
constexpr auto incomplete_beta_inv_ratio_val_1(
    const T value, const T alphaPar, const T betaPar, const T p, const T deriv1) noexcept -> T
{
    return (incomplete_beta_inv_err_val(value, alphaPar, betaPar, p) / deriv1);
}

template <typename T>
constexpr auto incomplete_beta_inv_ratio_val_2(
    const T value, const T alphaPar, const T betaPar, const T deriv1) noexcept -> T
{
    return (incomplete_beta_inv_deriv_2(value, alphaPar, betaPar, deriv1) / deriv1);
}

template <typename T>
constexpr auto incomplete_beta_inv_halley(const T ratioVal1, const T ratioVal2) noexcept -> T
{
    return (ratioVal1 / max(T(0.8), min(T(1.2), T(1) - T(0.5) * ratioVal1 * ratioVal2)));
}

template <typename T>
constexpr auto incomplete_beta_inv_recur(const T value, const T alphaPar, const T betaPar, const T p, const T deriv1,
    const T lbVal, int const iterCount) noexcept -> T
{
    return ( // derivative = 0
        etl::numeric_limits<T>::epsilon() > abs(deriv1)
            ? incomplete_beta_inv_decision(value, alphaPar, betaPar, p, T(0), lbVal, GCEM_INCML_BETA_INV_MAX_ITER + 1)
            :
            // else
            incomplete_beta_inv_decision(value, alphaPar, betaPar, p,
                incomplete_beta_inv_halley(incomplete_beta_inv_ratio_val_1(value, alphaPar, betaPar, p, deriv1),
                    incomplete_beta_inv_ratio_val_2(value, alphaPar, betaPar, deriv1)),
                lbVal, iterCount));
}

template <typename T>
constexpr auto incomplete_beta_inv_decision(const T value, const T alphaPar, const T betaPar, const T p, const T direc,
    const T lbVal, int const iterCount) noexcept -> T
{
    return (iterCount <= GCEM_INCML_BETA_INV_MAX_ITER ?
                                                      // if
                incomplete_beta_inv_recur(value - direc, alphaPar, betaPar, p,
                    incomplete_beta_inv_deriv_1(value, alphaPar, betaPar, lbVal), lbVal, iterCount + 1)
                                                      :
                                                      // else
                value - direc);
}

template <typename T>
constexpr auto incomplete_beta_inv_begin(
    const T initialVal, const T alphaPar, const T betaPar, const T p, const T lbVal) noexcept -> T
{
    return incomplete_beta_inv_recur(
        initialVal, alphaPar, betaPar, p, incomplete_beta_inv_deriv_1(initialVal, alphaPar, betaPar, lbVal), lbVal, 1);
}

template <typename T>
constexpr auto incomplete_beta_inv_check(const T alphaPar, const T betaPar, const T p) noexcept -> T
{
    return ( // NaN check
        any_nan(alphaPar, betaPar, p) ? etl::numeric_limits<T>::quiet_NaN() :
                                      // indistinguishable from zero or one
            etl::numeric_limits<T>::epsilon() > p           ? T(0)
        : etl::numeric_limits<T>::epsilon() > abs(T(1) - p) ? T(1)
                                                            :
                                                            // else
            incomplete_beta_inv_begin(
                incomplete_beta_inv_initial_val(alphaPar, betaPar, p), alphaPar, betaPar, p, lbeta(alphaPar, betaPar)));
}

template <typename T1, typename T2, typename T3, typename TC = common_t<T1, T2, T3>>
constexpr auto incomplete_beta_inv_type_check(const T1 a, const T2 b, const T3 p) noexcept -> TC
{
    return incomplete_beta_inv_check(static_cast<TC>(a), static_cast<TC>(b), static_cast<TC>(p));
}

} // namespace internal

/**
 * Compile-time inverse incomplete beta function
 *
 * @param a a real-valued, non-negative input.
 * @param b a real-valued, non-negative input.
 * @param p a real-valued input with values in the unit-interval.
 *
 * @return Computes the inverse incomplete beta function, a value \f$ x \f$ such
 * that \f[ f(x) := \frac{\text{B}(x;\alpha,\beta)}{\text{B}(\alpha,\beta)} - p
 * \f] equal to zero, for a given \c p. GCE-Math finds this root using Halley's
 * method: \f[ x_{n+1} = x_n - \frac{f(x_n)/f'(x_n)}{1 - 0.5
 * \frac{f(x_n)}{f'(x_n)} \frac{f''(x_n)}{f'(x_n)} } \f] where \f[
 * \frac{\partial}{\partial x}
 * \left(\frac{\text{B}(x;\alpha,\beta)}{\text{B}(\alpha,\beta)}\right) =
 * \frac{1}{\text{B}(\alpha,\beta)} x^{\alpha-1} (1-x)^{\beta-1} \f] \f[
 * \frac{\partial^2}{\partial x^2}
 * \left(\frac{\text{B}(x;\alpha,\beta)}{\text{B}(\alpha,\beta)}\right) =
 * \frac{1}{\text{B}(\alpha,\beta)} x^{\alpha-1} (1-x)^{\beta-1} \left(
 * \frac{\alpha-1}{x} - \frac{\beta-1}{1 - x} \right) \f]
 */

template <typename T1, typename T2, typename T3>
constexpr auto incomplete_beta_inv(const T1 a, const T2 b, const T3 p) noexcept -> common_t<T1, T2, T3>
{
    return internal::incomplete_beta_inv_type_check(a, b, p);
}

#endif
