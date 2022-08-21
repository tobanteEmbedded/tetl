/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CHRONO_ABS_HPP
#define TETL_CHRONO_ABS_HPP

#include "etl/_chrono/duration_cast.hpp"
#include "etl/_chrono/time_point_cast.hpp"
#include "etl/_limits/numeric_limits.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_arithmetic.hpp"

namespace etl::chrono {

/// \brief Returns the absolute value of the duration d. Specifically, if d >=
/// d.zero(), return d, otherwise return -d. The function does not participate
/// in the overload resolution unless etl::numeric_limits<R>::is_signed is
/// true.
template <typename R, typename P, enable_if_t<numeric_limits<R>::is_signed, int> = 0>
constexpr auto abs(duration<R, P> d) noexcept(is_arithmetic_v<R>) -> duration<R, P>
{
    return d < duration<R, P>::zero() ? duration<R, P>::zero() - d : d;
}

} // namespace etl::chrono

#endif // TETL_CHRONO_ABS_HPP
