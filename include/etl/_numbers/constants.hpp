// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#ifndef TETL_NUMBERS_CONSTANTS_HPP
#define TETL_NUMBERS_CONSTANTS_HPP

#include <etl/_config/all.hpp>

namespace etl::numbers {

/// \ingroup numbers
/// @{

// clang-format off
template <typename T> inline constexpr auto e_v           = static_cast<T>(2.7182818284590452353602874713526625L);
template <typename T> inline constexpr auto log2e_v       = static_cast<T>(1.4426950408889634073599246810018921L);
template <typename T> inline constexpr auto log10e_v      = static_cast<T>(0.4342944819032518276511289189166051L);
template <typename T> inline constexpr auto pi_v          = static_cast<T>(3.1415926535897932384626433832795028L);
template <typename T> inline constexpr auto inv_sqrtpi_v  = static_cast<T>(0.5641895835477562869480794515607725L);
template <typename T> inline constexpr auto inv_pi_v      = static_cast<T>(0.3183098861837906715377675267450287L);
template <typename T> inline constexpr auto ln2_v         = static_cast<T>(0.6931471805599453094172321214581766L);
template <typename T> inline constexpr auto ln10_v        = static_cast<T>(2.3025850929940456840179914546843642L);
template <typename T> inline constexpr auto sqrt2_v       = static_cast<T>(1.4142135623730950488016887242096981L);
template <typename T> inline constexpr auto sqrt3_v       = static_cast<T>(1.7320508075688772935274463415058724L);
template <typename T> inline constexpr auto inv_sqrt3_v   = static_cast<T>(0.5773502691896257645091487805019574L);
template <typename T> inline constexpr auto egamma_v      = static_cast<T>(0.5772156649015328606065120900824024L);
template <typename T> inline constexpr auto phi_v         = static_cast<T>(1.6180339887498948482045868343656381L);
// clang-format on

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

/// @}

} // namespace etl::numbers

#endif // TETL_NUMBERS_CONSTANTS_HPP
