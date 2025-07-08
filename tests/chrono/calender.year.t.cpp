// SPDX-License-Identifier: BSL-1.0

#include <etl/chrono.hpp>

#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

namespace chrono = etl::chrono;

[[nodiscard]] static constexpr auto test_year() -> bool
{
    using namespace etl::chrono_literals;

    // traits
    CHECK(etl::is_trivially_default_constructible_v<chrono::year>);
    CHECK(etl::is_nothrow_constructible_v<chrono::year, etl::int32_t>);
    CHECK(static_cast<int>(chrono::year::min()) == -32767);
    CHECK(static_cast<int>(chrono::year::max()) == +32767);

    // construct
    {
        auto y = chrono::year{};
        CHECK(y.ok());
        CHECK(static_cast<int>(y) == 0U);
    }

    {
        auto y = chrono::year{2024};
        CHECK(y.ok());
        CHECK(static_cast<int>(y) == 2024U);
    }

    // inc/dec
    {
        auto y = chrono::year{};

        ++y;
        CHECK(y == 1_y);

        y++;
        CHECK(y == 2_y);

        --y;
        CHECK(y == 1_y);

        y--;
        CHECK(y == 0_y);
    }

    // arithmetic
    {
        CHECK(1_y + chrono::years(3) == 4_y);
        CHECK(chrono::years(5) + 1_y == 6_y);

        auto y = chrono::year{2024};

        y += chrono::years{1};
        CHECK(y == 2025_y);

        y -= chrono::years{25};
        CHECK(y == 2000_y);
    }

    CHECK(2024_y - chrono::years(24) == 2000_y);
    CHECK(2024_y - 2000_y == chrono::years(24));

    CHECK(+chrono::year(1) == 1_y);
    CHECK(-chrono::year(1) == -1_y);

    // is_leap
    CHECK(chrono::year(2000).is_leap());
    CHECK(chrono::year(2004).is_leap());
    CHECK_FALSE(chrono::year(2023).is_leap());
    CHECK_FALSE(chrono::year(1900).is_leap());

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

[[nodiscard]] static constexpr auto test_year_month() -> bool
{
    // traits
    CHECK(etl::is_trivially_default_constructible_v<chrono::year_month>);
    CHECK(etl::is_nothrow_constructible_v<chrono::year_month, chrono::year, chrono::month>);

    {
        auto const ym = chrono::year_month{};
        CHECK_NOEXCEPT(ym.ok());
        CHECK_NOEXCEPT(ym.year());
        CHECK_NOEXCEPT(ym.month());
    }

    // construct
    {
        auto const ym = chrono::year_month{};
        CHECK_FALSE(ym.ok());
        CHECK(ym.year() == chrono::year(0));
        CHECK(ym.month() == chrono::month(0));
    }
    {
        auto const ym = chrono::year(1995) / chrono::month(5);
        CHECK(ym.ok());
        CHECK(ym.year() == chrono::year(1995));
        CHECK(ym.month() == chrono::month(5));
    }
    {
        auto const ym = chrono::year(1995) / chrono::month(13);
        CHECK_FALSE(ym.ok());
        CHECK(ym.year() == chrono::year(1995));
        CHECK(ym.month() == chrono::month(13));
    }
    {
        auto const min = etl::numeric_limits<etl::int16_t>::min();
        auto const ym  = chrono::year(min) / chrono::month(1);
        CHECK_FALSE(ym.ok());
        CHECK(ym.year() == chrono::year(min));
        CHECK(ym.month() == chrono::month(1));
    }

    // arithmetic
    {
        auto ym = chrono::year_month{};
        CHECK(ym.year() == chrono::year(0));
        CHECK(ym.month() == chrono::month(0));

        ym += chrono::years(1);
        CHECK(ym.year() == chrono::year(1));
        CHECK(ym.month() == chrono::month(0));

        ym += chrono::months(5);
        CHECK(ym.year() == chrono::year(1));
        CHECK(ym.month() == chrono::month(5));

        ym -= chrono::years(1);
        CHECK(ym.year() == chrono::year(0));
        CHECK(ym.month() == chrono::month(5));

        ym -= chrono::months(4);
        CHECK(ym.year() == chrono::year(0));
        CHECK(ym.month() == chrono::month(1));

        auto const ymp1 = ym + chrono::years(1);
        CHECK(ymp1.year() == chrono::year(1));
        CHECK(ymp1.month() == chrono::month(1));

        auto const ymp2 = chrono::years(2) + ym;
        CHECK(ymp2.year() == chrono::year(2));
        CHECK(ymp2.month() == chrono::month(1));
    }

    // compare
    {
        auto const birthday  = chrono::year(1995) / 5;
        auto const christmas = chrono::year(1995) / 12;
        CHECK(birthday == birthday);
        CHECK(christmas != birthday);
        CHECK(birthday != christmas);
    }

    return true;
}

[[nodiscard]] static constexpr auto test_year_month_day() -> bool
{
    using namespace etl::chrono_literals;

    // traits
    CHECK(etl::is_trivially_default_constructible_v<chrono::year_month_day>);
    CHECK(etl::is_nothrow_constructible_v<chrono::year_month_day, chrono::year, chrono::month, chrono::day>);
    CHECK(etl::is_nothrow_constructible_v<chrono::year_month_day, chrono::year_month_day_last>);
    CHECK(etl::is_nothrow_constructible_v<chrono::year_month_day, chrono::sys_days>);
    CHECK(etl::is_nothrow_constructible_v<chrono::year_month_day, chrono::local_days>);

    // construct
    {
        auto const ymd = chrono::year_month_day{};
        CHECK_FALSE(ymd.ok());
        CHECK(ymd.year() == 0_y);
        CHECK(ymd.month() == chrono::month(0));
        CHECK(ymd.day() == 0_d);
    }

    {
        auto const ymd = chrono::year_month_day{1995_y, chrono::month(5), 15_d};
        CHECK(ymd.ok());
        CHECK(ymd.year() == 1995_y);
        CHECK(ymd.month() == chrono::month(5));
        CHECK(ymd.day() == 15_d);
        CHECK(ymd == (1995_y / 5 / 15));
        CHECK(ymd == (15_d / 5 / 1995_y));
        CHECK(ymd == (15_d / 5 / 1995));
    }

    {
        auto const ymd = chrono::year_month_day{chrono::sys_days(chrono::days(0))};
        CHECK(ymd.ok());
        CHECK(ymd.year() == 1970_y);
        CHECK(ymd.month() == chrono::month(1));
        CHECK(ymd.day() == 1_d);
        CHECK(static_cast<chrono::sys_days>(ymd) == chrono::sys_days(chrono::days(0)));
    }

    {
        auto const ymd = chrono::year_month_day{chrono::sys_days(chrono::days(1000))};
        CHECK(ymd.ok());
        CHECK(ymd.year() == 1972_y);
        CHECK(ymd.month() == chrono::September);
        CHECK(ymd.day() == 27_d);
        CHECK(static_cast<chrono::sys_days>(ymd) == chrono::sys_days(chrono::days(1000)));
    }

    {
        auto const ymd = chrono::year_month_day{chrono::sys_days(chrono::days(10000))};
        CHECK(ymd.ok());
        CHECK(ymd.year() == 1997_y);
        CHECK(ymd.month() == chrono::May);
        CHECK(ymd.day() == 19_d);
        CHECK(static_cast<chrono::sys_days>(ymd) == chrono::sys_days(chrono::days(10000)));
    }

    {
        auto const ymd = chrono::year_month_day{chrono::sys_days(chrono::days(20000))};
        CHECK(ymd.ok());
        CHECK(ymd.year() == 2024_y);
        CHECK(ymd.month() == chrono::October);
        CHECK(ymd.day() == 4_d);
        CHECK(static_cast<chrono::sys_days>(ymd) == chrono::sys_days(chrono::days(20000)));
    }

    {
        auto const ymd = chrono::year_month_day{chrono::sys_days(chrono::days(100'000))};
        CHECK(ymd.ok());
        CHECK(ymd.year() == 2243_y);
        CHECK(ymd.month() == chrono::October);
        CHECK(ymd.day() == 17_d);
        CHECK(static_cast<chrono::sys_days>(ymd) == chrono::sys_days(chrono::days(100'000)));
    }

    {
        auto const ymd = chrono::year_month_day{chrono::sys_days(chrono::days(-10000))};
        CHECK(ymd.ok());
        CHECK(ymd.year() == 1942_y);
        CHECK(ymd.month() == chrono::August);
        CHECK(ymd.day() == 16_d);
        CHECK(static_cast<chrono::sys_days>(ymd) == chrono::sys_days(chrono::days(-10000)));
    }

    {
        auto const ymd = chrono::year_month_day{chrono::sys_days(chrono::days(-20000))};
        CHECK(ymd.ok());
        CHECK(ymd.year() == 1915_y);
        CHECK(ymd.month() == chrono::March);
        CHECK(ymd.day() == 31_d);
        CHECK(static_cast<chrono::sys_days>(ymd) == chrono::sys_days(chrono::days(-20000)));
    }

    {
        auto const ymd = chrono::year_month_day{chrono::sys_days(chrono::days(-100'000))};
        CHECK(ymd.ok());
        CHECK(ymd.year() == 1696_y);
        CHECK(ymd.month() == chrono::March);
        CHECK(ymd.day() == 17_d);
        CHECK(static_cast<chrono::sys_days>(ymd) == chrono::sys_days(chrono::days(-100'000)));
    }

    {
        auto const ymd = chrono::year_month_day{chrono::sys_days(chrono::days(-719'468))};
        CHECK(ymd.ok());
        CHECK(ymd.year() == 0_y);
        CHECK(ymd.month() == chrono::March);
        CHECK(ymd.day() == 1_d);
        CHECK(static_cast<chrono::sys_days>(ymd) == chrono::sys_days(chrono::days(-719'468)));
    }

    {
        auto const ymd = chrono::year_month_day{chrono::sys_days(chrono::days(-719'469))};
        CHECK(ymd.ok());
        CHECK(ymd.year() == 0_y);
        CHECK(ymd.month() == chrono::February);
        CHECK(ymd.day() == 29_d);
        CHECK(static_cast<chrono::sys_days>(ymd) == chrono::sys_days(chrono::days(-719'469)));
    }

    // arithmetic
    {
        auto const epoch     = chrono::year_month_day{chrono::sys_days(chrono::days(0))};
        auto const nextMonth = epoch + chrono::months(1);
        CHECK(nextMonth.year() == 1970_y);
        CHECK(nextMonth.month() == chrono::month(2));
        CHECK(nextMonth.day() == 1_d);

        auto const afterNextMonth = chrono::months(2) + epoch;
        CHECK(afterNextMonth.year() == 1970_y);
        CHECK(afterNextMonth.month() == chrono::month(3));
        CHECK(afterNextMonth.day() == 1_d);
    }

    // {
    //     auto const epoch     = chrono::year_month_day{chrono::sys_days(chrono::days(0))};
    //     auto const prevMonth = epoch - chrono::months(1);
    //     CHECK(prevMonth.year() == 1969_y);
    //     CHECK(prevMonth.month() == chrono::month(12));
    //     CHECK(prevMonth.day() == 1_d);
    // }

    return true;
}

[[nodiscard]] static constexpr auto test_year_month_day_last() -> bool
{
    // traits
    CHECK(etl::is_nothrow_constructible_v<chrono::year_month_day_last, chrono::year, chrono::month_day_last>);

    // construct
    {
        auto const ymd = chrono::year(1995) / 5 / chrono::last;
        CHECK(ymd.ok());
        CHECK(ymd.year() == chrono::year(1995));
        CHECK(ymd.month() == chrono::month(5));
        CHECK(ymd.day() == chrono::day(31));
    }

    {
        auto const ymd = chrono::May / chrono::last / chrono::year(1995);
        CHECK(ymd.ok());
        CHECK(ymd.year() == chrono::year(1995));
        CHECK(ymd.month() == chrono::month(5));
        CHECK(ymd.day() == chrono::day(31));
    }

    {
        auto const ymd = chrono::May / chrono::last / 1995;
        CHECK(ymd.ok());
        CHECK(ymd.year() == chrono::year(1995));
        CHECK(ymd.month() == chrono::month(5));
        CHECK(ymd.day() == chrono::day(31));
    }

    {
        auto const ymd = 1995 / (chrono::February / chrono::last);
        CHECK(ymd.ok());
        CHECK(ymd.year() == chrono::year(1995));
        CHECK(ymd.month() == chrono::month(2));
        CHECK(ymd.day() == chrono::day(28));
    }

    {
        auto const ymd = chrono::year(2020) / (chrono::February / chrono::last);
        CHECK(ymd.ok());
        CHECK(ymd.year() == chrono::year(2020));
        CHECK(ymd.month() == chrono::month(2));
        CHECK(ymd.day() == chrono::day(29));
    }

    {
        auto const min = etl::numeric_limits<etl::int16_t>::min();
        CHECK_FALSE((chrono::year(2020) / (chrono::month(13) / chrono::last)).ok()); // invalid month
        CHECK_FALSE((chrono::year(min) / (chrono::month(1) / chrono::last)).ok());   // invalid year
    }

    return true;
}

[[nodiscard]] static constexpr auto test_year_month_weekday() -> bool
{
    using namespace etl::chrono_literals;
    using chrono::year_month_weekday;

    // traits
    CHECK(etl::is_trivially_default_constructible_v<year_month_weekday>);
    CHECK(etl::is_nothrow_constructible_v<year_month_weekday, chrono::sys_days>);
    CHECK(etl::is_nothrow_constructible_v<year_month_weekday, chrono::local_days>);
    CHECK(etl::is_nothrow_constructible_v<year_month_weekday, chrono::year, chrono::month, chrono::weekday_indexed>);

    // construct
    {
        auto const ymd = year_month_weekday{chrono::year(1995), chrono::May, chrono::Monday[2]};
        CHECK(ymd.ok());
        CHECK(ymd.year() == chrono::year(1995));
        CHECK(ymd.month() == chrono::May);
        CHECK(ymd.weekday() == chrono::Monday);
        CHECK(ymd.weekday_indexed() == chrono::Monday[2]);
    }

    {
        auto const ymd = year_month_weekday{chrono::year(1970), chrono::January, chrono::Monday[6]};
        CHECK_FALSE(ymd.ok()); // invalid index
        CHECK(ymd.year() == chrono::year(1970));
        CHECK(ymd.month() == chrono::January);
        CHECK(ymd.weekday() == chrono::Monday);
        CHECK(ymd.weekday_indexed() == chrono::Monday[6]);
    }

    {
        auto const ymd = year_month_weekday{chrono::year(1970), chrono::month(13), chrono::Monday[1]};
        CHECK_FALSE(ymd.ok()); // invalid month
        CHECK(ymd.year() == chrono::year(1970));
        CHECK(ymd.month() == chrono::month(13));
        CHECK(ymd.weekday() == chrono::Monday);
        CHECK(ymd.weekday_indexed() == chrono::Monday[1]);
    }

    return true;
}

[[nodiscard]] static constexpr auto test_all() -> bool
{
    CHECK(test_year());
    CHECK(test_year_month());
    CHECK(test_year_month_day());
    CHECK(test_year_month_day_last());
    CHECK(test_year_month_weekday());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
