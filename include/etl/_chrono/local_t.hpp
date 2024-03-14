// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_LOCAL_T_HPP
#define TETL_CHRONO_LOCAL_T_HPP

#include <etl/_chrono/duration.hpp>
#include <etl/_chrono/time_point.hpp>

namespace etl::chrono {

/// @brief The class local_t is a pseudo-clock that is used as the first
///        template argument to etl::chrono::time_point to indicate that
///        the time point represents local time with respect of a
///        not-yet-specified time zone. local_time supports streaming and
///        the full set of time point arithmetic.
struct local_t { };

template <typename Duration>
using local_time    = etl::chrono::time_point<etl::chrono::local_t, Duration>;
using local_seconds = local_time<etl::chrono::seconds>;
using local_days    = local_time<etl::chrono::days>;

} // namespace etl::chrono

#endif // TETL_CHRONO_LOCAL_T_HPP
