// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPLEX_REAL_HPP
#define TETL_COMPLEX_REAL_HPP

#include <etl/_complex/complex.hpp>
#include <etl/_concepts/floating_point.hpp>
#include <etl/_concepts/integral.hpp>

namespace etl {

/// \ingroup complex
template <typename T>
[[nodiscard]] constexpr auto real(complex<T> const& z) noexcept(noexcept(z.real())) -> T
{
    return z.real();
}

/// \ingroup complex
template <floating_point Float>
[[nodiscard]] constexpr auto real(Float f) noexcept -> Float
{
    return f;
}

/// \ingroup complex
template <integral Integer>
[[nodiscard]] constexpr auto real(Integer i) noexcept -> double
{
    return static_cast<double>(i);
}

} // namespace etl

#endif // TETL_COMPLEX_REAL_HPP
