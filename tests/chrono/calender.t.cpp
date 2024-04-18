// SPDX-License-Identifier: BSL-1.0

#include <etl/chrono.hpp>

#include <etl/type_traits.hpp>

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
    using namespace etl::chrono_literals;

    // traits
    CHECK(etl::is_trivially_default_constructible_v<etl::chrono::day>);

    // construct
    auto d = etl::chrono::day{};
    CHECK_FALSE(d.ok());
    CHECK(static_cast<etl::uint32_t>(d) == 0U);

    // inc/dec
    ++d;
    CHECK(d == 1_d);

    ++d;
    CHECK(d == 2_d);

    --d;
    CHECK(d == 1_d);

    // ok
    CHECK(etl::chrono::day(1).ok());
    CHECK(etl::chrono::day(2).ok());
    CHECK(etl::chrono::day(30).ok());
    CHECK(etl::chrono::day(31).ok());
    CHECK_FALSE(etl::chrono::day(0).ok());
    CHECK_FALSE(etl::chrono::day(32).ok());

    // compare
    CHECK(1_d == 1_d);
    CHECK(1_d != 2_d);
    CHECK(2_d != 1_d);

    CHECK(1_d < 2_d);
    CHECK_FALSE(2_d < 1_d);

    CHECK(1_d <= 1_d);
    CHECK(1_d <= 2_d);
    CHECK_FALSE(2_d <= 1_d);

    CHECK(2_d > 1_d);
    CHECK_FALSE(1_d > 1_d);
    CHECK_FALSE(1_d > 2_d);

    CHECK(2_d >= 1_d);
    CHECK(1_d >= 1_d);
    CHECK_FALSE(1_d >= 2_d);

    return true;
}

[[nodiscard]] constexpr auto test_month() -> bool
{
    // traits
    CHECK(etl::is_trivially_default_constructible_v<etl::chrono::month>);

    // construct
    auto m = etl::chrono::month{};
    CHECK(static_cast<etl::uint32_t>(m) == 0U);
    CHECK_FALSE(m.ok());

    // inc/dec
    ++m;
    CHECK(m == etl::chrono::month(1));

    ++m;
    CHECK(m == etl::chrono::month(2));

    --m;
    CHECK(m == etl::chrono::month(1));

    // ok
    CHECK(etl::chrono::month(1).ok());
    CHECK(etl::chrono::month(2).ok());
    CHECK(etl::chrono::month(11).ok());
    CHECK(etl::chrono::month(12).ok());
    CHECK_FALSE(etl::chrono::month(0).ok());
    CHECK_FALSE(etl::chrono::month(13).ok());

    // compare
    CHECK(etl::chrono::month(1) == etl::chrono::month(1));
    CHECK(etl::chrono::month(1) != etl::chrono::month(2));
    CHECK(etl::chrono::month(2) != etl::chrono::month(1));

    CHECK(etl::chrono::month(1) < etl::chrono::month(2));
    CHECK_FALSE(etl::chrono::month(2) < etl::chrono::month(1));

    CHECK(etl::chrono::month(1) <= etl::chrono::month(1));
    CHECK(etl::chrono::month(1) <= etl::chrono::month(2));
    CHECK_FALSE(etl::chrono::month(2) <= etl::chrono::month(1));

    CHECK(etl::chrono::month(2) > etl::chrono::month(1));
    CHECK_FALSE(etl::chrono::month(1) > etl::chrono::month(1));
    CHECK_FALSE(etl::chrono::month(1) > etl::chrono::month(2));

    CHECK(etl::chrono::month(2) >= etl::chrono::month(1));
    CHECK(etl::chrono::month(1) >= etl::chrono::month(1));
    CHECK_FALSE(etl::chrono::month(1) >= etl::chrono::month(2));

    // constants
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

    return true;
}

[[nodiscard]] constexpr auto test_year() -> bool
{
    using namespace etl::chrono_literals;

    // traits
    CHECK(etl::is_trivially_default_constructible_v<etl::chrono::year>);
    CHECK(etl::is_nothrow_constructible_v<etl::chrono::year, etl::int32_t>);
    CHECK(static_cast<etl::int32_t>(etl::chrono::year::min()) == -32767);
    CHECK(static_cast<etl::int32_t>(etl::chrono::year::max()) == +32767);

    // construct
    {
        auto y = etl::chrono::year{};
        CHECK(y.ok());
        CHECK(static_cast<etl::int32_t>(y) == 0U);
    }

    {
        auto y = etl::chrono::year{2024};
        CHECK(y.ok());
        CHECK(static_cast<etl::int32_t>(y) == 2024U);
    }

    // inc/dec
    {
        auto y = etl::chrono::year{};

        ++y;
        CHECK(y == 1_y);

        y++;
        CHECK(y == 2_y);

        --y;
        CHECK(y == 1_y);

        y--;
        CHECK(y == 0_y);
    }

    // arithemtic
    {
        CHECK(1_y + etl::chrono::years(3) == 4_y);
        CHECK(etl::chrono::years(5) + 1_y == 6_y);

        auto y = etl::chrono::year{2024};

        y += etl::chrono::years{1};
        CHECK(y == 2025_y);

        y -= etl::chrono::years{25};
        CHECK(y == 2000_y);
    }

    CHECK(2024_y - etl::chrono::years(24) == 2000_y);
    CHECK(2024_y - 2000_y == etl::chrono::years(24));

    CHECK(+etl::chrono::year(1) == 1_y);
    CHECK(-etl::chrono::year(1) == -1_y);

    // is_leap
    CHECK(etl::chrono::year(2000).is_leap());
    CHECK(etl::chrono::year(2004).is_leap());
    CHECK_FALSE(etl::chrono::year(2023).is_leap());
    CHECK_FALSE(etl::chrono::year(1900).is_leap());

    // compare
    CHECK(1_y == 1_y);
    CHECK(1_y != 2_y);
    CHECK(2_y != 1_y);

    CHECK(1_y < 2_y);
    CHECK_FALSE(2_y < 1_y);

    CHECK(1_y <= 1_y);
    CHECK(1_y <= 2_y);
    CHECK_FALSE(2_y <= 1_y);

    CHECK(2_y > 1_y);
    CHECK_FALSE(1_y > 1_y);
    CHECK_FALSE(1_y > 2_y);

    CHECK(2_y >= 1_y);
    CHECK(1_y >= 1_y);
    CHECK_FALSE(1_y >= 2_y);

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
