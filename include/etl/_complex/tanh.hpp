// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_COMPLEX_TANH_HPP
#define TETL_COMPLEX_TANH_HPP

#include <etl/_complex/complex.hpp>
#include <etl/_complex/cosh.hpp>
#include <etl/_complex/sinh.hpp>

namespace etl {

/// \ingroup complex
template <typename T>
[[nodiscard]] constexpr auto tanh(complex<T> const& z) -> complex<T>
{
    return etl::sinh(z) / etl::cosh(z);
}

} // namespace etl

#endif // TETL_COMPLEX_TANH_HPP
