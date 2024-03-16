// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPLEX_LOG_HPP
#define TETL_COMPLEX_LOG_HPP

#include <etl/_cmath/log.hpp>
#include <etl/_complex/arg.hpp>
#include <etl/_complex/complex.hpp>
#include <etl/_math/abs.hpp>

namespace etl {

template <typename T>
[[nodiscard]] constexpr auto log(complex<T> const& z) noexcept -> complex<T>
{
    return {etl::log(etl::abs(z)), etl::arg(z)};
}

} // namespace etl

#endif // TETL_COMPLEX_LOG_HPP
