// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_COMPLEX_SIN_HPP
#define TETL_COMPLEX_SIN_HPP

#include <etl/_complex/complex.hpp>
#include <etl/_complex/sinh.hpp>

namespace etl {

/// \ingroup complex
template <typename T>
[[nodiscard]] constexpr auto sin(complex<T> const& z) -> complex<T>
{
    auto const x = z.real();
    auto const y = z.imag();
    return {
        etl::sin(x) * etl::cosh(y),
        etl::cos(x) * etl::sinh(y),
    };
}

} // namespace etl

#endif // TETL_COMPLEX_SIN_HPP
