// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_COMPLEX_LOG10_HPP
#define TETL_COMPLEX_LOG10_HPP

#include <etl/_complex/complex.hpp>
#include <etl/_complex/log.hpp>

namespace etl {

/// \ingroup complex
template <typename T>
[[nodiscard]] constexpr auto log10(complex<T> const& z) noexcept -> complex<T>
{
    return etl::log(z) / etl::log(T(10));
}

} // namespace etl

#endif // TETL_COMPLEX_LOG10_HPP
