// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_ABS_HPP
#define TETL_CHRONO_ABS_HPP

#include <etl/_chrono/duration_cast.hpp>
#include <etl/_chrono/time_point_cast.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_type_traits/is_arithmetic.hpp>

namespace etl::chrono {

/// Returns the absolute value of the duration d. Specifically, if d >= d.zero(),
/// return d, otherwise return -d. The function does not participate in the
/// overload resolution unless etl::numeric_limits<R>::is_signed is true.
/// \ingroup chrono
template <typename R, typename P>
    requires(numeric_limits<R>::is_signed)
constexpr auto abs(duration<R, P> d) noexcept(is_arithmetic_v<R>) -> duration<R, P>
{
    return d < duration<R, P>::zero() ? duration<R, P>::zero() - d : d;
}

} // namespace etl::chrono

#endif // TETL_CHRONO_ABS_HPP
