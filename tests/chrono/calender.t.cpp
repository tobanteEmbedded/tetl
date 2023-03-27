/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/chrono.hpp"

#include "testing/testing.hpp"

[[nodiscard]] constexpr auto test_duration() -> bool
{
    assert(etl::chrono::days(1) == etl::chrono::hours(24));
    assert(etl::chrono::days(2) == etl::chrono::hours(48));
    assert(etl::chrono::days(7) == etl::chrono::weeks(1));
    assert(etl::chrono::days(14) == etl::chrono::weeks(2));
    return true;
}

[[nodiscard]] constexpr auto test_day() -> bool
{
    assert(etl::chrono::day(1).ok());
    assert(etl::chrono::day(2).ok());
    assert(etl::chrono::day(30).ok());
    assert(etl::chrono::day(31).ok());
    assert(not etl::chrono::day(0).ok());
    assert(not etl::chrono::day(32).ok());

    auto d = etl::chrono::day {};
    assert(not d.ok());
    assert(static_cast<etl::uint32_t>(d) == 0U);

    ++d;
    assert(d == etl::chrono::day(1));

    ++d;
    assert(d == etl::chrono::day(2));

    --d;
    assert(d == etl::chrono::day(1));

    return true;
}

[[nodiscard]] constexpr auto test_month() -> bool
{
    assert(etl::chrono::month(1).ok());
    assert(etl::chrono::month(2).ok());
    assert(etl::chrono::month(11).ok());
    assert(etl::chrono::month(12).ok());
    assert(not etl::chrono::month(0).ok());
    assert(not etl::chrono::month(13).ok());

    assert(etl::chrono::month(1) == etl::chrono::January);
    assert(etl::chrono::month(2) == etl::chrono::February);
    assert(etl::chrono::month(3) == etl::chrono::March);
    assert(etl::chrono::month(4) == etl::chrono::April);
    assert(etl::chrono::month(5) == etl::chrono::May);
    assert(etl::chrono::month(6) == etl::chrono::June);
    assert(etl::chrono::month(7) == etl::chrono::July);
    assert(etl::chrono::month(8) == etl::chrono::August);
    assert(etl::chrono::month(9) == etl::chrono::September);
    assert(etl::chrono::month(10) == etl::chrono::October);
    assert(etl::chrono::month(11) == etl::chrono::November);
    assert(etl::chrono::month(12) == etl::chrono::December);

    auto m = etl::chrono::month {};
    assert(not m.ok());
    assert(static_cast<etl::uint32_t>(m) == 0U);

    ++m;
    assert(m == etl::chrono::month(1));

    ++m;
    assert(m == etl::chrono::month(2));

    --m;
    assert(m == etl::chrono::month(1));

    return true;
}

[[nodiscard]] constexpr auto test_year() -> bool
{
    assert(etl::chrono::year(2000).is_leap());
    assert(etl::chrono::year(2004).is_leap());
    assert(not etl::chrono::year(2023).is_leap());
    assert(not etl::chrono::year(1900).is_leap());

    auto y = etl::chrono::year {};
    assert(y.ok());
    assert(static_cast<etl::int32_t>(y) == 0U);

    ++y;
    assert(y == etl::chrono::year(1));

    ++y;
    assert(y == etl::chrono::year(2));

    --y;
    assert(y == etl::chrono::year(1));

    return true;
}

[[nodiscard]] constexpr auto test_all() -> bool
{
    assert(test_duration());
    assert(test_day());
    assert(test_month());
    assert(test_year());
    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
