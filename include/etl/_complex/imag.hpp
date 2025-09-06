// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_COMPLEX_IMAG_HPP
#define TETL_COMPLEX_IMAG_HPP

#include <etl/_complex/complex.hpp>
#include <etl/_concepts/floating_point.hpp>
#include <etl/_concepts/integral.hpp>

namespace etl {

/// \ingroup complex
template <typename T>
[[nodiscard]] constexpr auto imag(complex<T> const& z) noexcept(noexcept(z.imag())) -> T
{
    return z.imag();
}

/// \ingroup complex
template <floating_point Float>
[[nodiscard]] constexpr auto imag(Float /*f*/) noexcept -> Float
{
    return Float{};
}

/// \ingroup complex
template <integral Integer>
[[nodiscard]] constexpr auto imag(Integer /*i*/) noexcept -> double
{
    return 0.0;
}

} // namespace etl

#endif // TETL_COMPLEX_IMAG_HPP
