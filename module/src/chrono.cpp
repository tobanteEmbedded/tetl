module;

#include <etl/chrono.hpp>

export module etl.chrono;

export namespace etl {

namespace chrono {

using etl::chrono::abs;
using etl::chrono::ceil;
using etl::chrono::day;
using etl::chrono::days;
using etl::chrono::duration;
using etl::chrono::duration_cast;
using etl::chrono::duration_values;
using etl::chrono::floor;
using etl::chrono::hours;
using etl::chrono::is_clock;
using etl::chrono::last;
using etl::chrono::last_spec;
using etl::chrono::local_days;
using etl::chrono::local_t;
using etl::chrono::month;
using etl::chrono::month_day;
using etl::chrono::month_day_last;
using etl::chrono::month_weekday;
using etl::chrono::month_weekday_last;
using etl::chrono::months;
using etl::chrono::round;
using etl::chrono::sys_days;
using etl::chrono::sys_seconds;
using etl::chrono::sys_time;
using etl::chrono::system_clock;
using etl::chrono::time_point;
using etl::chrono::time_point_cast;
using etl::chrono::treat_as_floating_point;
using etl::chrono::weekday;
using etl::chrono::weekday_indexed;
using etl::chrono::weekday_last;
using etl::chrono::weeks;
using etl::chrono::year;
using etl::chrono::year_month;
using etl::chrono::year_month_day;
using etl::chrono::year_month_day_last;
using etl::chrono::year_month_weekday;
using etl::chrono::year_month_weekday_last;
using etl::chrono::years;

using etl::chrono::operator==;
using etl::chrono::operator!=;
using etl::chrono::operator<;
using etl::chrono::operator<=;
using etl::chrono::operator>;
using etl::chrono::operator>=;
using etl::chrono::operator+;
using etl::chrono::operator-;
using etl::chrono::operator/;
using etl::chrono::operator%;

using etl::chrono::days;
using etl::chrono::hours;
using etl::chrono::microseconds;
using etl::chrono::milliseconds;
using etl::chrono::minutes;
using etl::chrono::months;
using etl::chrono::nanoseconds;
using etl::chrono::seconds;
using etl::chrono::weeks;
using etl::chrono::years;

using etl::chrono::Friday;
using etl::chrono::Monday;
using etl::chrono::Saturday;
using etl::chrono::Sunday;
using etl::chrono::Thursday;
using etl::chrono::Tuesday;
using etl::chrono::Wednesday;

using etl::chrono::April;
using etl::chrono::August;
using etl::chrono::December;
using etl::chrono::February;
using etl::chrono::January;
using etl::chrono::July;
using etl::chrono::June;
using etl::chrono::March;
using etl::chrono::May;
using etl::chrono::November;
using etl::chrono::October;
using etl::chrono::September;

} // namespace chrono

inline namespace literals {
inline namespace chrono_literals {

using etl::literals::chrono_literals::operator""_h;
using etl::literals::chrono_literals::operator""_min;
using etl::literals::chrono_literals::operator""_s;
using etl::literals::chrono_literals::operator""_ms;
using etl::literals::chrono_literals::operator""_us;
using etl::literals::chrono_literals::operator""_ns;
using etl::literals::chrono_literals::operator""_d;
using etl::literals::chrono_literals::operator""_y;

} // namespace chrono_literals
} // namespace literals

} // namespace etl
