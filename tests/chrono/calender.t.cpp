// SPDX-License-Identifier: BSL-1.0

#include <etl/chrono.hpp>

#include "testing/testing.hpp"

[[nodiscard]] constexpr auto test_duration() -> bool
{
    CHECK(etl::chrono::days(1) == etl::chrono::hours(24));
    CHECK(etl::chrono::days(2) == etl::chrono::hours(48));
    CHECK(etl::chrono::days(7) == etl::chrono::weeks(1));
    CHECK(etl::chrono::days(14) == etl::chrono::weeks(2));
    return true;
}

[[nodiscard]] constexpr auto test_day() -> bool
{
    CHECK(etl::chrono::day(1).ok());
    CHECK(etl::chrono::day(2).ok());
    CHECK(etl::chrono::day(30).ok());
    CHECK(etl::chrono::day(31).ok());
    CHECK_FALSE(etl::chrono::day(0).ok());
    CHECK_FALSE(etl::chrono::day(32).ok());

    auto d = etl::chrono::day{};
    CHECK_FALSE(d.ok());
    CHECK(static_cast<etl::uint32_t>(d) == 0U);

    ++d;
    CHECK(d == etl::chrono::day(1));

    ++d;
    CHECK(d == etl::chrono::day(2));

    --d;
    CHECK(d == etl::chrono::day(1));

    return true;
}

[[nodiscard]] constexpr auto test_month() -> bool
{
    CHECK(etl::chrono::month(1).ok());
    CHECK(etl::chrono::month(2).ok());
    CHECK(etl::chrono::month(11).ok());
    CHECK(etl::chrono::month(12).ok());
    CHECK_FALSE(etl::chrono::month(0).ok());
    CHECK_FALSE(etl::chrono::month(13).ok());

    CHECK(etl::chrono::month(1) == etl::chrono::January);
    CHECK(etl::chrono::month(2) == etl::chrono::February);
    CHECK(etl::chrono::month(3) == etl::chrono::March);
    CHECK(etl::chrono::month(4) == etl::chrono::April);
    CHECK(etl::chrono::month(5) == etl::chrono::May);
    CHECK(etl::chrono::month(6) == etl::chrono::June);
    CHECK(etl::chrono::month(7) == etl::chrono::July);
    CHECK(etl::chrono::month(8) == etl::chrono::August);
    CHECK(etl::chrono::month(9) == etl::chrono::September);
    CHECK(etl::chrono::month(10) == etl::chrono::October);
    CHECK(etl::chrono::month(11) == etl::chrono::November);
    CHECK(etl::chrono::month(12) == etl::chrono::December);

    auto m = etl::chrono::month{};
    CHECK_FALSE(m.ok());
    CHECK(static_cast<etl::uint32_t>(m) == 0U);

    ++m;
    CHECK(m == etl::chrono::month(1));

    ++m;
    CHECK(m == etl::chrono::month(2));

    --m;
    CHECK(m == etl::chrono::month(1));

    return true;
}

[[nodiscard]] constexpr auto test_year() -> bool
{
    CHECK(etl::chrono::year(2000).is_leap());
    CHECK(etl::chrono::year(2004).is_leap());
    CHECK_FALSE(etl::chrono::year(2023).is_leap());
    CHECK_FALSE(etl::chrono::year(1900).is_leap());

    auto y = etl::chrono::year{};
    CHECK(y.ok());
    CHECK(static_cast<etl::int32_t>(y) == 0U);

    ++y;
    CHECK(y == etl::chrono::year(1));

    ++y;
    CHECK(y == etl::chrono::year(2));

    --y;
    CHECK(y == etl::chrono::year(1));

    return true;
}

[[nodiscard]] constexpr auto test_all() -> bool
{
    CHECK(test_duration());
    CHECK(test_day());
    CHECK(test_month());
    CHECK(test_year());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
