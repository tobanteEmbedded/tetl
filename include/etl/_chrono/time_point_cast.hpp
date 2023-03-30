// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_TIME_POINT_CAST_HPP
#define TETL_CHRONO_TIME_POINT_CAST_HPP

#include "etl/_chrono/duration_cast.hpp"
#include "etl/_chrono/time_point.hpp"

namespace etl::chrono {

template <typename ToDuration, typename Clock, typename Duration>
    requires(detail::is_duration_v<ToDuration>)
[[nodiscard]] constexpr auto time_point_cast(time_point<Clock, Duration> const& tp) -> ToDuration
{
    using time_point_t = time_point<Clock, ToDuration>;
    return time_point_t(duration_cast<ToDuration>(tp.time_since_epoch()));
}

} // namespace etl::chrono

#endif // TETL_CHRONO_TIME_POINT_CAST_HPP
