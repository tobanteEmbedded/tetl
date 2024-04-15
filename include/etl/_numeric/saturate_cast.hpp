// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_NUMERIC_SATURATE_CAST_HPP
#define TETL_NUMERIC_SATURATE_CAST_HPP

#include <etl/_concepts/builtin_integer.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_utility/cmp_greater.hpp>
#include <etl/_utility/cmp_less.hpp>

namespace etl {

/// Converts the value x to a value of type T, clamping x between
/// the minimum and maximum values of type T.
///
/// \ingroup numeric
template <builtin_integer T, builtin_integer U>
[[nodiscard]] constexpr auto saturate_cast(U x) noexcept -> T
{
    if (etl::cmp_less(x, etl::numeric_limits<T>::min())) {
        return etl::numeric_limits<T>::min();
    }
    if (etl::cmp_greater(x, etl::numeric_limits<T>::max())) {
        return etl::numeric_limits<T>::max();
    }
    return static_cast<T>(x);
}

} // namespace etl

#endif // TETL_NUMERIC_SATURATE_CAST_HPP
