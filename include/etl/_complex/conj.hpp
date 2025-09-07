// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_COMPLEX_CONJ_HPP
#define TETL_COMPLEX_CONJ_HPP

#include <etl/_complex/complex.hpp>
#include <etl/_concepts/floating_point.hpp>
#include <etl/_concepts/integral.hpp>

namespace etl {

/// \ingroup complex
template <typename T>
[[nodiscard]] constexpr auto conj(complex<T> const& z) noexcept -> complex<T>
{
    return complex<T>(z.real(), -z.imag());
}

/// \ingroup complex
template <floating_point Float>
[[nodiscard]] constexpr auto conj(Float f) noexcept -> complex<Float>
{
    return complex<Float>(f);
}

/// \ingroup complex
template <integral Integer>
[[nodiscard]] constexpr auto conj(Integer i) noexcept -> complex<double>
{
    return complex<double>(static_cast<double>(i));
}

} // namespace etl

#endif // TETL_COMPLEX_CONJ_HPP
