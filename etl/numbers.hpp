/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_NUMBERS_HPP
#define TAETL_NUMBERS_HPP

#include "type_traits.hpp"

namespace etl::numbers
{
template <class T>
inline constexpr auto e_v = static_cast<T>(2.7182818284590452353602874713526625L);
template <class T>
inline constexpr auto log2e_v = static_cast<T>(1.4426950408889634073599246810018921L);
template <class T>
inline constexpr auto log10e_v = static_cast<T>(0.4342944819032518276511289189166051L);
template <class T>
inline constexpr auto pi_v = static_cast<T>(3.1415926535897932384626433832795028L);
template <class T>
inline constexpr auto inv_sqrtpi_v = static_cast<T>(0.564189583547756286948079451560772L);
template <class T>
inline constexpr auto inv_pi_v = static_cast<T>(0.3183098861837906715377675267450287L);
template <class T>
inline constexpr auto ln2_v = static_cast<T>(0.6931471805599453094172321214581766L);
template <class T>
inline constexpr auto ln10_v = static_cast<T>(2.3025850929940456840179914546843642L);
template <class T>
inline constexpr auto sqrt2_v = static_cast<T>(1.4142135623730950488016887242096981L);
template <class T>
inline constexpr auto sqrt3_v = static_cast<T>(1.7320508075688772935274463415058724L);
template <class T>
inline constexpr auto inv_sqrt3_v = static_cast<T>(0.5773502691896257645091487805019574L);
template <class T>
inline constexpr auto egamma_v = static_cast<T>(0.5772156649015328606065120900824024L);
template <class T>
inline constexpr auto phi_v = static_cast<T>(1.6180339887498948482045868343656381L);

inline constexpr float ef          = e_v<float>;
inline constexpr float log2ef      = log2e_v<float>;
inline constexpr float log10ef     = log10e_v<float>;
inline constexpr float pif         = pi_v<float>;
inline constexpr float inv_pif     = inv_pi_v<float>;
inline constexpr float inv_sqrtpif = inv_sqrtpi_v<float>;
inline constexpr float ln2f        = ln2_v<float>;
inline constexpr float ln10f       = ln10_v<float>;
inline constexpr float sqrt2f      = sqrt2_v<float>;
inline constexpr float sqrt3f      = sqrt3_v<float>;
inline constexpr float inv_sqrt3f  = inv_sqrt3_v<float>;
inline constexpr float egammaf     = egamma_v<float>;
inline constexpr float phif        = phi_v<float>;

inline constexpr double e          = e_v<double>;
inline constexpr double log2e      = log2e_v<double>;
inline constexpr double log10e     = log10e_v<double>;
inline constexpr double pi         = pi_v<double>;
inline constexpr double inv_pi     = inv_pi_v<double>;
inline constexpr double inv_sqrtpi = inv_sqrtpi_v<double>;
inline constexpr double ln2        = ln2_v<double>;
inline constexpr double ln10       = ln10_v<double>;
inline constexpr double sqrt2      = sqrt2_v<double>;
inline constexpr double sqrt3      = sqrt3_v<double>;
inline constexpr double inv_sqrt3  = inv_sqrt3_v<double>;
inline constexpr double egamma     = egamma_v<double>;
inline constexpr double phi        = phi_v<double>;

inline constexpr long double el          = e_v<long double>;
inline constexpr long double log2el      = log2e_v<long double>;
inline constexpr long double log10el     = log10e_v<long double>;
inline constexpr long double pil         = pi_v<long double>;
inline constexpr long double inv_pil     = inv_pi_v<long double>;
inline constexpr long double inv_sqrtpil = inv_sqrtpi_v<long double>;
inline constexpr long double ln2l        = ln2_v<long double>;
inline constexpr long double ln10l       = ln10_v<long double>;
inline constexpr long double sqrt2l      = sqrt2_v<long double>;
inline constexpr long double sqrt3l      = sqrt3_v<long double>;
inline constexpr long double inv_sqrt3l  = inv_sqrt3_v<long double>;
inline constexpr long double egammal     = egamma_v<long double>;
inline constexpr long double phil        = phi_v<long double>;

}  // namespace etl::numbers

#endif  // TAETL_NUMBERS_HPP
