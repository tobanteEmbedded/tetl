// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPLEX_LOG10_HPP
#define TETL_COMPLEX_LOG10_HPP

#include "etl/_complex/complex.hpp"
#include "etl/_complex/log.hpp"

namespace etl {

template <typename T>
[[nodiscard]] constexpr auto log10(complex<T> const& z) noexcept -> complex<T>
{
    return log(z) / log(T(10));
}

} // namespace etl

#endif // TETL_COMPLEX_LOG10_HPP
