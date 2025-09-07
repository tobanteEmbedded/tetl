// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_COMPLEX_TAN_HPP
#define TETL_COMPLEX_TAN_HPP

#include <etl/_complex/complex.hpp>
#include <etl/_complex/cos.hpp>
#include <etl/_complex/sin.hpp>

namespace etl {

/// \ingroup complex
template <typename T>
[[nodiscard]] constexpr auto tan(complex<T> const& z) -> complex<T>
{
    return etl::sin(z) / etl::cos(z);
}

} // namespace etl

#endif // TETL_COMPLEX_TAN_HPP
