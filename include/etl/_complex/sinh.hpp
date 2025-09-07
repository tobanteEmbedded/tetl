// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_COMPLEX_SINH_HPP
#define TETL_COMPLEX_SINH_HPP

#include <etl/_cmath/cos.hpp>
#include <etl/_cmath/cosh.hpp>
#include <etl/_cmath/sin.hpp>
#include <etl/_cmath/sinh.hpp>
#include <etl/_complex/complex.hpp>

namespace etl {

/// \ingroup complex
template <typename T>
[[nodiscard]] constexpr auto sinh(complex<T> const& z) -> complex<T>
{
    auto const x = z.real();
    auto const y = z.imag();
    return {
        etl::sinh(x) * etl::cos(y),
        etl::cosh(x) * etl::sin(y),
    };
}

} // namespace etl

#endif // TETL_COMPLEX_SINH_HPP
