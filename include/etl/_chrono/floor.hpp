// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_FLOOR_HPP
#define TETL_CHRONO_FLOOR_HPP

#include "etl/_chrono/duration_cast.hpp"
#include "etl/_chrono/time_point_cast.hpp"
#include "etl/_type_traits/is_arithmetic.hpp"

namespace etl::chrono {

/// \brief Returns the greatest duration t representable in ToDuration that is
/// less or equal to d. The function does not participate in the overload
/// resolution unless ToDuration is an instance of etl::chrono::duration.
template <typename To, typename Rep, typename Period>
    requires(detail::is_duration_v<To>)
[[nodiscard]] constexpr auto floor(duration<Rep, Period> const& d) noexcept(
    is_arithmetic_v<Rep>&& is_arithmetic_v<typename To::rep>) -> To
{
    auto const t {duration_cast<To>(d)};
    if (t > d) { return To(t.count() - static_cast<typename To::rep>(1)); }
    return t;
}

template <typename To, typename Clock, typename Duration>
    requires(detail::is_duration_v<To>)
[[nodiscard]] constexpr auto floor(time_point<Clock, Duration> const& tp) -> time_point<Clock, To>
{
    return time_point<Clock, To>(floor<To>(tp.time_since_epoch()));
}

} // namespace etl::chrono

#endif // TETL_CHRONO_FLOOR_HPP
