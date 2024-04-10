// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPLEX_NORM_HPP
#define TETL_COMPLEX_NORM_HPP

#include <etl/_complex/complex.hpp>
#include <etl/_concepts/floating_point.hpp>
#include <etl/_concepts/integral.hpp>

namespace etl {

/// \ingroup complex
template <typename T>
[[nodiscard]] constexpr auto norm(complex<T> const& z) noexcept -> T
{
    auto const x = z.real();
    auto const y = z.imag();
    return x * x + y * y;
}

/// \ingroup complex
template <floating_point Float>
[[nodiscard]] constexpr auto norm(Float f) noexcept -> complex<Float>
{
    return etl::norm(etl::complex<Float>(f));
}

/// \ingroup complex
template <integral Integer>
[[nodiscard]] constexpr auto norm(Integer i) noexcept -> complex<double>
{
    return etl::norm(etl::complex<double>(i));
}

} // namespace etl

#endif // TETL_COMPLEX_NORM_HPP
