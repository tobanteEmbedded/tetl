// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_SYSTEM_CLOCK_HPP
#define TETL_CHRONO_SYSTEM_CLOCK_HPP

#include <etl/_chrono/duration.hpp>
#include <etl/_chrono/duration_cast.hpp>
#include <etl/_cstdint/int_t.hpp>
#include <etl/_ctime/time_t.hpp>
#include <etl/_ratio/ratio.hpp>

namespace etl::chrono {

/// \ingroup chrono
struct system_clock {
    using rep                       = int32_t;
    using period                    = micro;
    using duration                  = chrono::duration<rep, period>;
    using time_point                = chrono::time_point<system_clock>;
    static constexpr bool is_steady = false;

    [[nodiscard]] static auto now() noexcept -> time_point { return {}; }

    [[nodiscard]] static auto to_time_t(time_point const& t) noexcept -> time_t
    {
        return static_cast<time_t>(duration_cast<seconds>(t.time_since_epoch()).count());
    }

    [[nodiscard]] static auto from_time_t(time_t t) noexcept -> time_point
    {
        return time_point{seconds{static_cast<seconds::rep>(t)}};
    }
};

template <typename Duration>
using sys_time = chrono::time_point<chrono::system_clock, Duration>;

using sys_seconds = sys_time<chrono::seconds>;
using sys_days    = sys_time<chrono::days>;

} // namespace etl::chrono

#endif // TETL_CHRONO_SYSTEM_CLOCK_HPP
