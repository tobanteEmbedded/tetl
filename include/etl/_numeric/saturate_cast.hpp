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
template <builtin_integer To, builtin_integer From>
[[nodiscard]] constexpr auto saturate_cast(From x) noexcept -> To
{
    if (etl::cmp_less(x, etl::numeric_limits<To>::min())) {
        return etl::numeric_limits<To>::min();
    }
    if (etl::cmp_greater(x, etl::numeric_limits<To>::max())) {
        return etl::numeric_limits<To>::max();
    }
    return static_cast<To>(x);
}

} // namespace etl

#endif // TETL_NUMERIC_SATURATE_CAST_HPP
