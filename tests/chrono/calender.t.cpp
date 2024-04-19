// SPDX-License-Identifier: BSL-1.0

#include <etl/chrono.hpp>

#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

namespace chrono = etl::chrono;

[[nodiscard]] constexpr auto test_duration() -> bool
{
    CHECK(chrono::days(1) == chrono::hours(24));
    CHECK(chrono::days(2) == chrono::hours(48));
    CHECK(chrono::days(7) == chrono::weeks(1));
    CHECK(chrono::days(14) == chrono::weeks(2));
    return true;
}

[[nodiscard]] constexpr auto test_day() -> bool
{
    using namespace etl::chrono_literals;

    // traits
    CHECK(etl::is_trivially_default_constructible_v<chrono::day>);

    // construct
    auto d = chrono::day{};
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
    CHECK(chrono::day(1).ok());
    CHECK(chrono::day(2).ok());
    CHECK(chrono::day(30).ok());
    CHECK(chrono::day(31).ok());
    CHECK_FALSE(chrono::day(0).ok());
    CHECK_FALSE(chrono::day(32).ok());

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
    CHECK(etl::is_trivially_default_constructible_v<chrono::month>);

    // construct
    auto m = chrono::month{};
    CHECK(static_cast<etl::uint32_t>(m) == 0U);
    CHECK_FALSE(m.ok());

    // inc/dec
    ++m;
    CHECK(m == chrono::month(1));

    ++m;
    CHECK(m == chrono::month(2));

    --m;
    CHECK(m == chrono::month(1));

    // ok
    CHECK(chrono::month(1).ok());
    CHECK(chrono::month(2).ok());
    CHECK(chrono::month(11).ok());
    CHECK(chrono::month(12).ok());
    CHECK_FALSE(chrono::month(0).ok());
    CHECK_FALSE(chrono::month(13).ok());

    // compare
    CHECK(chrono::month(1) == chrono::month(1));
    CHECK(chrono::month(1) != chrono::month(2));
    CHECK(chrono::month(2) != chrono::month(1));

    CHECK(chrono::month(1) < chrono::month(2));
    CHECK_FALSE(chrono::month(2) < chrono::month(1));

    CHECK(chrono::month(1) <= chrono::month(1));
    CHECK(chrono::month(1) <= chrono::month(2));
    CHECK_FALSE(chrono::month(2) <= chrono::month(1));

    CHECK(chrono::month(2) > chrono::month(1));
    CHECK_FALSE(chrono::month(1) > chrono::month(1));
    CHECK_FALSE(chrono::month(1) > chrono::month(2));

    CHECK(chrono::month(2) >= chrono::month(1));
    CHECK(chrono::month(1) >= chrono::month(1));
    CHECK_FALSE(chrono::month(1) >= chrono::month(2));

    // constants
    CHECK(chrono::month(1) == chrono::January);
    CHECK(chrono::month(2) == chrono::February);
    CHECK(chrono::month(3) == chrono::March);
    CHECK(chrono::month(4) == chrono::April);
    CHECK(chrono::month(5) == chrono::May);
    CHECK(chrono::month(6) == chrono::June);
    CHECK(chrono::month(7) == chrono::July);
    CHECK(chrono::month(8) == chrono::August);
    CHECK(chrono::month(9) == chrono::September);
    CHECK(chrono::month(10) == chrono::October);
    CHECK(chrono::month(11) == chrono::November);
    CHECK(chrono::month(12) == chrono::December);

    return true;
}

[[nodiscard]] constexpr auto test_year() -> bool
{
    using namespace etl::chrono_literals;

    // traits
    CHECK(etl::is_trivially_default_constructible_v<chrono::year>);
    CHECK(etl::is_nothrow_constructible_v<chrono::year, etl::int32_t>);
    CHECK(static_cast<etl::int32_t>(chrono::year::min()) == -32767);
    CHECK(static_cast<etl::int32_t>(chrono::year::max()) == +32767);

    // construct
    {
        auto y = chrono::year{};
        CHECK(y.ok());
        CHECK(static_cast<etl::int32_t>(y) == 0U);
    }

    {
        auto y = chrono::year{2024};
        CHECK(y.ok());
        CHECK(static_cast<etl::int32_t>(y) == 2024U);
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

[[nodiscard]] constexpr auto test_weekday() -> bool
{
    using namespace etl::chrono_literals;

    // traits
    CHECK(etl::is_trivially_default_constructible_v<chrono::weekday>);
    CHECK(etl::is_nothrow_constructible_v<chrono::weekday, unsigned>);
    CHECK(etl::is_nothrow_constructible_v<chrono::weekday, chrono::sys_days>);
    CHECK(etl::is_nothrow_constructible_v<chrono::weekday, chrono::local_days>);

    {
        auto const wd = chrono::weekday{};
        CHECK_NOEXCEPT(wd.ok());
        CHECK_NOEXCEPT(wd.c_encoding());
        CHECK_NOEXCEPT(wd.iso_encoding());
        CHECK_NOEXCEPT(wd == chrono::weekday{1});
    }

    // construct
    {
        auto wd = chrono::weekday{};
        CHECK(wd.ok());
        CHECK(wd.c_encoding() == 0U);
        CHECK(wd.iso_encoding() == 7U);
    }

    {
        auto wd = chrono::weekday{6};
        CHECK(wd.ok());
        CHECK(wd.c_encoding() == 6U);
        CHECK(wd.iso_encoding() == 6U);
    }

    {
        auto wd = chrono::weekday{8};
        CHECK_FALSE(wd.ok());
    }

    {
        auto const wd = chrono::weekday{chrono::sys_days(chrono::days(-4))};
        CHECK(wd.c_encoding() == 0U);
        CHECK(wd.iso_encoding() == 7U);
    }

    {
        auto const wd = chrono::weekday{chrono::local_days(chrono::days(-4))};
        CHECK(wd.c_encoding() == 0U);
        CHECK(wd.iso_encoding() == 7U);
    }

    // inc/dec
    {
        auto wd = chrono::weekday{};

        ++wd;
        CHECK(wd == chrono::weekday(1));

        wd++;
        CHECK(wd == chrono::weekday(2));

        --wd;
        CHECK(wd == chrono::weekday(1));

        wd--;
        CHECK(wd == chrono::weekday(0));
    }

    // arithmetic
    {
        auto wd = chrono::weekday{};

        wd += chrono::days(1);
        CHECK(wd.c_encoding() == 1);

        wd += chrono::days(2);
        CHECK(wd.c_encoding() == 3);

        wd -= chrono::days(1);
        CHECK(wd.c_encoding() == 2);

        CHECK((chrono::Monday - chrono::days(1)) == chrono::Sunday);
        CHECK((chrono::Monday + chrono::days(1)) == chrono::Tuesday);
        CHECK((chrono::days(1) + chrono::Monday) == chrono::Tuesday);
    }

    // compare
    CHECK(chrono::weekday(1) == chrono::weekday(1));
    CHECK(chrono::weekday(1) != chrono::weekday(2));
    CHECK(chrono::weekday(2) != chrono::weekday(1));

    CHECK(chrono::Sunday == chrono::weekday(0));
    CHECK(chrono::Monday == chrono::weekday(1));
    CHECK(chrono::Tuesday == chrono::weekday(2));
    CHECK(chrono::Wednesday == chrono::weekday(3));
    CHECK(chrono::Thursday == chrono::weekday(4));
    CHECK(chrono::Friday == chrono::weekday(5));
    CHECK(chrono::Saturday == chrono::weekday(6));
    CHECK(chrono::Sunday == chrono::weekday(7));

    return true;
}

[[nodiscard]] constexpr auto test_weekday_indexed() -> bool
{
    // traits
    CHECK(etl::is_trivially_default_constructible_v<chrono::weekday_indexed>);
    CHECK(etl::is_nothrow_constructible_v<chrono::weekday_indexed, chrono::weekday, etl::uint32_t>);

    {
        auto const wdi = chrono::weekday_indexed{};
        CHECK_NOEXCEPT(wdi.ok());
        CHECK_NOEXCEPT(wdi.weekday());
        CHECK_NOEXCEPT(wdi.index());
        CHECK_NOEXCEPT(wdi == chrono::weekday_indexed{});
    }

    // construct
    {
        auto const wdi = chrono::weekday_indexed{};
        CHECK(wdi.weekday() == chrono::weekday());
        CHECK(wdi.index() == 0);
        CHECK_FALSE(wdi.ok());
    }
    {
        auto const wdi = chrono::weekday_indexed{chrono::Monday, 1};
        CHECK(wdi.weekday() == chrono::Monday);
        CHECK(wdi.index() == 1);
        CHECK(wdi.ok());
    }

    // compare
    auto const empty        = chrono::weekday_indexed{};
    auto const firstMonday  = chrono::weekday_indexed{chrono::Monday, 1};
    auto const secondMonday = chrono::weekday_indexed{chrono::Monday, 2};

    CHECK(empty == empty);
    CHECK(firstMonday == firstMonday);
    CHECK(secondMonday == secondMonday);

    CHECK(empty != firstMonday);
    CHECK(empty != secondMonday);
    CHECK(firstMonday != secondMonday);

    CHECK(firstMonday == chrono::Monday[1]);
    CHECK(firstMonday != chrono::Monday[2]);

    return true;
}

[[nodiscard]] constexpr auto test_weekday_last() -> bool
{
    // traits
    CHECK(etl::is_nothrow_constructible_v<chrono::weekday_last, chrono::weekday>);

    {
        auto const wdl = chrono::weekday_last{chrono::Monday};
        CHECK_NOEXCEPT(wdl.ok());
        CHECK_NOEXCEPT(wdl.weekday());
        CHECK_NOEXCEPT(wdl == chrono::weekday_last{chrono::Monday});
    }

    // construct
    {
        auto const wdl = chrono::weekday_last{chrono::Monday};
        CHECK(wdl.ok());
        CHECK(wdl.weekday() == chrono::Monday);
    }

    // compare
    {
        auto const wdl = chrono::weekday_last{chrono::Monday};
        CHECK(wdl == chrono::weekday_last{chrono::Monday});
        CHECK(wdl != chrono::weekday_last{chrono::Tuesday});
        CHECK(wdl == chrono::Monday[chrono::last]);
        CHECK(wdl != chrono::Tuesday[chrono::last]);
    }

    return true;
}

[[nodiscard]] constexpr auto test_month_day() -> bool
{
    // traits
    CHECK(etl::is_trivially_default_constructible_v<chrono::month_day>);
    CHECK(etl::is_nothrow_constructible_v<chrono::month_day, chrono::month, chrono::day>);

    {
        auto const md = chrono::month_day{};
        CHECK_NOEXCEPT(md.month());
        CHECK_NOEXCEPT(md.day());
        CHECK_NOEXCEPT(md.ok());
    }

    // construct
    {
        auto const md = chrono::month_day{};
        CHECK_FALSE(md.ok());
        CHECK(md.month() == chrono::month(0));
        CHECK(md.day() == chrono::day(0));
    }
    {
        auto const md = chrono::month_day{chrono::month(5), chrono::day(15)};
        CHECK(md.ok());
        CHECK(md.day() == chrono::day(15));
        CHECK(md.month() == chrono::month(5));
    }
    {
        auto const md = chrono::month(13) / 15;
        CHECK_FALSE(md.ok());
        CHECK(md.day() == chrono::day(15));
        CHECK(md.month() == chrono::month(13));
    }

    // ok
    {
        CHECK((chrono::month(1) / 31).ok());
        CHECK((chrono::month(2) / 28).ok());
        CHECK((chrono::month(12) / 15).ok());

        CHECK_FALSE((chrono::month(1) / chrono::day(0)).ok());
        CHECK_FALSE((chrono::month(1) / chrono::day(32)).ok());
        CHECK_FALSE((2 / chrono::day(30)).ok());
        CHECK_FALSE((chrono::day(15) / 13).ok());
    }

    // compare
    {
        auto const birthday  = chrono::month_day{chrono::month(5), chrono::day(15)};
        auto const christmas = chrono::month_day{chrono::month(12), chrono::day(24)};
        CHECK(birthday == birthday);
        CHECK(christmas != birthday);
        CHECK(birthday != christmas);
    }

    return true;
}

[[nodiscard]] constexpr auto test_month_day_last() -> bool
{
    // traits
    CHECK(etl::is_nothrow_constructible_v<chrono::month_day_last, chrono::month>);

    {
        auto const md = chrono::month_day_last{chrono::January};
        CHECK_NOEXCEPT(md.month());
        CHECK_NOEXCEPT(md.ok());
    }

    // construct
    {
        auto const md = chrono::month_day_last{chrono::January};
        CHECK(md.ok());
        CHECK(md.month() == chrono::January);
    }
    {
        auto const md = chrono::last / chrono::May;
        CHECK(md.ok());
        CHECK(md.month() == chrono::May);
    }
    {
        auto const md = chrono::month(13) / chrono::last;
        CHECK_FALSE(md.ok());
        CHECK(md.month() == chrono::month(13));
    }

    // compare
    {
        auto const birthday  = chrono::last / 5;
        auto const christmas = 12 / chrono::last;
        CHECK(birthday == birthday);
        CHECK(christmas != birthday);
        CHECK(birthday != christmas);
    }

    return true;
}

[[nodiscard]] constexpr auto test_month_weekday() -> bool
{
    // traits
    CHECK(etl::is_nothrow_constructible_v<chrono::month_weekday, chrono::month, chrono::weekday_indexed>);

    {
        auto const md = chrono::month_weekday(chrono::January, {chrono::Monday, 1});
        CHECK_NOEXCEPT(md.month());
        CHECK_NOEXCEPT(md.weekday_indexed());
        CHECK_NOEXCEPT(md.ok());
    }

    // construct
    {
        auto const md = chrono::month_weekday(chrono::January, {chrono::Monday, 1});
        CHECK(md.ok());
        CHECK(md.month() == chrono::January);
        CHECK(md.weekday_indexed() == chrono::weekday_indexed(chrono::Monday, 1));
    }

    {
        auto const md = chrono::Monday[6] / 1;
        CHECK_FALSE(md.ok());
        CHECK(md.month() == chrono::January);
        CHECK(md.weekday_indexed() == chrono::weekday_indexed(chrono::Monday, 6));
    }

    {
        auto const md = 13 / chrono::Monday[1];
        CHECK_FALSE(md.ok());
        CHECK(md.month() == chrono::month(13));
        CHECK(md.weekday_indexed() == chrono::weekday_indexed(chrono::Monday, 1));
    }

    // compare
    {
        auto const first  = chrono::January / chrono::Monday[1];
        auto const second = chrono::Monday[2] / chrono::January;
        CHECK(first == first);
        CHECK(second != first);
        CHECK(first != second);
    }

    return true;
}

[[nodiscard]] constexpr auto test_year_month() -> bool
{
    // traits
    CHECK(etl::is_trivially_default_constructible_v<etl::chrono::year_month>);
    CHECK(etl::is_nothrow_constructible_v<etl::chrono::year_month, etl::chrono::year, etl::chrono::month>);

    {
        auto const ym = etl::chrono::year_month{};
        CHECK_NOEXCEPT(ym.ok());
        CHECK_NOEXCEPT(ym.year());
        CHECK_NOEXCEPT(ym.month());
    }

    // construct
    {
        auto const ym = etl::chrono::year_month{};
        CHECK_FALSE(ym.ok());
        CHECK(ym.year() == etl::chrono::year(0));
        CHECK(ym.month() == etl::chrono::month(0));
    }
    {
        auto const ym = etl::chrono::year(1995) / etl::chrono::month(5);
        CHECK(ym.ok());
        CHECK(ym.year() == etl::chrono::year(1995));
        CHECK(ym.month() == etl::chrono::month(5));
    }
    {
        auto const ym = etl::chrono::year(1995) / etl::chrono::month(13);
        CHECK_FALSE(ym.ok());
        CHECK(ym.year() == etl::chrono::year(1995));
        CHECK(ym.month() == etl::chrono::month(13));
    }

    // arithmetic
    {
        auto ym = etl::chrono::year_month{};
        CHECK(ym.year() == etl::chrono::year(0));
        CHECK(ym.month() == etl::chrono::month(0));

        ym += etl::chrono::years(1);
        CHECK(ym.year() == etl::chrono::year(1));
        CHECK(ym.month() == etl::chrono::month(0));

        ym += etl::chrono::months(5);
        CHECK(ym.year() == etl::chrono::year(1));
        CHECK(ym.month() == etl::chrono::month(5));

        ym -= etl::chrono::years(1);
        CHECK(ym.year() == etl::chrono::year(0));
        CHECK(ym.month() == etl::chrono::month(5));

        ym -= etl::chrono::months(4);
        CHECK(ym.year() == etl::chrono::year(0));
        CHECK(ym.month() == etl::chrono::month(1));

        auto const ymp1 = ym + etl::chrono::years(1);
        CHECK(ymp1.year() == etl::chrono::year(1));
        CHECK(ymp1.month() == etl::chrono::month(1));

        auto const ymp2 = etl::chrono::years(2) + ym;
        CHECK(ymp2.year() == etl::chrono::year(2));
        CHECK(ymp2.month() == etl::chrono::month(1));
    }

    // compare
    {
        auto const birthday  = etl::chrono::year(1995) / 5;
        auto const christmas = etl::chrono::year(1995) / 12;
        CHECK(birthday == birthday);
        CHECK(christmas != birthday);
        CHECK(birthday != christmas);
    }

    return true;
}

[[nodiscard]] constexpr auto test_all() -> bool
{
    CHECK(test_duration());

    CHECK(test_day());
    CHECK(test_month());
    CHECK(test_year());

    CHECK(test_weekday());
    CHECK(test_weekday_indexed());
    CHECK(test_weekday_last());

    CHECK(test_month_day());
    CHECK(test_month_day_last());
    CHECK(test_month_weekday());

    CHECK(test_year_month());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
