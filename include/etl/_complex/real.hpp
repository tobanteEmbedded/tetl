// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPLEX_REAL_HPP
#define TETL_COMPLEX_REAL_HPP

#include <etl/_complex/complex.hpp>
#include <etl/_type_traits/enable_if.hpp>
#include <etl/_type_traits/is_floating_point.hpp>
#include <etl/_type_traits/is_integral.hpp>

namespace etl {

/// \ingroup complex
template <typename T>
[[nodiscard]] constexpr auto real(complex<T> const& z) -> T
{
    return z.real();
}

/// \ingroup complex
template <typename Float>
[[nodiscard]] constexpr auto real(Float f) noexcept -> enable_if_t<is_floating_point_v<Float>, Float>
{
    return f;
}

/// \ingroup complex
template <typename Integer>
[[nodiscard]] constexpr auto real(Integer i) noexcept -> enable_if_t<is_integral_v<Integer>, double>
{
    return static_cast<double>(i);
}

} // namespace etl

#endif // TETL_COMPLEX_REAL_HPP
