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

    // arithmetic
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

[[nodiscard]] constexpr auto test_weekday() -> bool
{
    using namespace etl::chrono_literals;

    // traits
    CHECK(etl::is_trivially_default_constructible_v<etl::chrono::weekday>);
    CHECK(etl::is_nothrow_constructible_v<etl::chrono::weekday, unsigned>);
    CHECK(etl::is_nothrow_constructible_v<etl::chrono::weekday, etl::chrono::sys_days>);
    CHECK(etl::is_nothrow_constructible_v<etl::chrono::weekday, etl::chrono::local_days>);

    {
        auto const wd = etl::chrono::weekday{};
        CHECK_NOEXCEPT(wd.ok());
        CHECK_NOEXCEPT(wd.c_encoding());
        CHECK_NOEXCEPT(wd.iso_encoding());
        CHECK_NOEXCEPT(wd == etl::chrono::weekday{1});
    }

    // construct
    {
        auto wd = etl::chrono::weekday{};
        CHECK(wd.ok());
        CHECK(wd.c_encoding() == 0U);
        CHECK(wd.iso_encoding() == 7U);
    }

    {
        auto wd = etl::chrono::weekday{6};
        CHECK(wd.ok());
        CHECK(wd.c_encoding() == 6U);
        CHECK(wd.iso_encoding() == 6U);
    }

    {
        auto wd = etl::chrono::weekday{8};
        CHECK_FALSE(wd.ok());
    }

    {
        auto const wd = etl::chrono::weekday{etl::chrono::sys_days(etl::chrono::days(-4))};
        CHECK(wd.c_encoding() == 0U);
        CHECK(wd.iso_encoding() == 7U);
    }

    {
        auto const wd = etl::chrono::weekday{etl::chrono::local_days(etl::chrono::days(-4))};
        CHECK(wd.c_encoding() == 0U);
        CHECK(wd.iso_encoding() == 7U);
    }

    // inc/dec
    {
        auto wd = etl::chrono::weekday{};

        ++wd;
        CHECK(wd == etl::chrono::weekday(1));

        wd++;
        CHECK(wd == etl::chrono::weekday(2));

        --wd;
        CHECK(wd == etl::chrono::weekday(1));

        wd--;
        CHECK(wd == etl::chrono::weekday(0));
    }

    // arithmetic
    {
        auto wd = etl::chrono::weekday{};

        wd += etl::chrono::days(1);
        CHECK(wd.c_encoding() == 1);

        wd += etl::chrono::days(2);
        CHECK(wd.c_encoding() == 3);

        wd -= etl::chrono::days(1);
        CHECK(wd.c_encoding() == 2);

        CHECK((etl::chrono::Monday - etl::chrono::days(1)) == etl::chrono::Sunday);
        CHECK((etl::chrono::Monday + etl::chrono::days(1)) == etl::chrono::Tuesday);
        CHECK((etl::chrono::days(1) + etl::chrono::Monday) == etl::chrono::Tuesday);
    }

    // compare
    CHECK(etl::chrono::weekday(1) == etl::chrono::weekday(1));
    CHECK(etl::chrono::weekday(1) != etl::chrono::weekday(2));
    CHECK(etl::chrono::weekday(2) != etl::chrono::weekday(1));

    CHECK(etl::chrono::Sunday == etl::chrono::weekday(0));
    CHECK(etl::chrono::Monday == etl::chrono::weekday(1));
    CHECK(etl::chrono::Tuesday == etl::chrono::weekday(2));
    CHECK(etl::chrono::Wednesday == etl::chrono::weekday(3));
    CHECK(etl::chrono::Thursday == etl::chrono::weekday(4));
    CHECK(etl::chrono::Friday == etl::chrono::weekday(5));
    CHECK(etl::chrono::Saturday == etl::chrono::weekday(6));
    CHECK(etl::chrono::Sunday == etl::chrono::weekday(7));

    return true;
}

[[nodiscard]] constexpr auto test_weekday_indexed() -> bool
{
    // traits
    CHECK(etl::is_trivially_default_constructible_v<etl::chrono::weekday_indexed>);
    CHECK(etl::is_nothrow_constructible_v<etl::chrono::weekday_indexed, etl::chrono::weekday, etl::uint32_t>);

    {
        auto const wdi = etl::chrono::weekday_indexed{};
        CHECK_NOEXCEPT(wdi.ok());
        CHECK_NOEXCEPT(wdi.weekday());
        CHECK_NOEXCEPT(wdi.index());
        CHECK_NOEXCEPT(wdi == etl::chrono::weekday_indexed{});
    }

    // construct
    {
        auto const wdi = etl::chrono::weekday_indexed{};
        CHECK(wdi.weekday() == etl::chrono::weekday());
        CHECK(wdi.index() == 0);
        CHECK_FALSE(wdi.ok());
    }
    {
        auto const wdi = etl::chrono::weekday_indexed{etl::chrono::Monday, 1};
        CHECK(wdi.weekday() == etl::chrono::Monday);
        CHECK(wdi.index() == 1);
        CHECK(wdi.ok());
    }

    // compare
    auto const empty        = etl::chrono::weekday_indexed{};
    auto const firstMonday  = etl::chrono::weekday_indexed{etl::chrono::Monday, 1};
    auto const secondMonday = etl::chrono::weekday_indexed{etl::chrono::Monday, 2};

    CHECK(empty == empty);
    CHECK(firstMonday == firstMonday);
    CHECK(secondMonday == secondMonday);

    CHECK(empty != firstMonday);
    CHECK(empty != secondMonday);
    CHECK(firstMonday != secondMonday);

    CHECK(firstMonday == etl::chrono::Monday[1]);
    CHECK(firstMonday != etl::chrono::Monday[2]);

    return true;
}

[[nodiscard]] constexpr auto test_weekday_last() -> bool
{
    // traits
    CHECK(etl::is_nothrow_constructible_v<etl::chrono::weekday_last, etl::chrono::weekday>);

    {
        auto const wdl = etl::chrono::weekday_last{etl::chrono::Monday};
        CHECK_NOEXCEPT(wdl.ok());
        CHECK_NOEXCEPT(wdl.weekday());
        CHECK_NOEXCEPT(wdl == etl::chrono::weekday_last{etl::chrono::Monday});
    }

    // construct
    {
        auto const wdl = etl::chrono::weekday_last{etl::chrono::Monday};
        CHECK(wdl.ok());
        CHECK(wdl.weekday() == etl::chrono::Monday);
    }

    // compare
    {
        auto const wdl = etl::chrono::weekday_last{etl::chrono::Monday};
        CHECK(wdl == etl::chrono::weekday_last{etl::chrono::Monday});
        CHECK(wdl != etl::chrono::weekday_last{etl::chrono::Tuesday});
        CHECK(wdl == etl::chrono::Monday[etl::chrono::last]);
        CHECK(wdl != etl::chrono::Tuesday[etl::chrono::last]);
    }

    return true;
}

[[nodiscard]] constexpr auto test_month_day() -> bool
{
    // traits
    CHECK(etl::is_trivially_default_constructible_v<etl::chrono::month_day>);
    CHECK(etl::is_nothrow_constructible_v<etl::chrono::month_day, etl::chrono::month, etl::chrono::day>);

    {
        auto const md = etl::chrono::month_day{};
        CHECK_NOEXCEPT(md.month());
        CHECK_NOEXCEPT(md.day());
        CHECK_NOEXCEPT(md.ok());
    }

    // construct
    {
        auto const md = etl::chrono::month_day{};
        CHECK_FALSE(md.ok());
        CHECK(md.month() == etl::chrono::month(0));
        CHECK(md.day() == etl::chrono::day(0));
    }
    {
        auto const md = etl::chrono::month_day{etl::chrono::month(5), etl::chrono::day(15)};
        CHECK(md.ok());
        CHECK(md.day() == etl::chrono::day(15));
        CHECK(md.month() == etl::chrono::month(5));
    }
    {
        auto const md = etl::chrono::month_day{etl::chrono::month(13), etl::chrono::day(15)};
        CHECK_FALSE(md.ok());
        CHECK(md.day() == etl::chrono::day(15));
        CHECK(md.month() == etl::chrono::month(13));
    }

    // ok
    {
        CHECK(etl::chrono::month_day{etl::chrono::month(1), etl::chrono::day(31)}.ok());
        CHECK(etl::chrono::month_day{etl::chrono::month(2), etl::chrono::day(28)}.ok());
        CHECK(etl::chrono::month_day{etl::chrono::month(12), etl::chrono::day(15)}.ok());

        CHECK_FALSE(etl::chrono::month_day{etl::chrono::month(1), etl::chrono::day(32)}.ok());
        CHECK_FALSE(etl::chrono::month_day{etl::chrono::month(2), etl::chrono::day(30)}.ok());
        CHECK_FALSE(etl::chrono::month_day{etl::chrono::month(13), etl::chrono::day(15)}.ok());
    }

    // compare
    {
        auto const birthday  = etl::chrono::month_day{etl::chrono::month(5), etl::chrono::day(15)};
        auto const christmas = etl::chrono::month_day{etl::chrono::month(12), etl::chrono::day(24)};
        CHECK(birthday == birthday);
        CHECK(christmas != birthday);
        CHECK(birthday != christmas);
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
        auto const ym = etl::chrono::year_month{etl::chrono::year(1995), etl::chrono::month(5)};
        CHECK(ym.ok());
        CHECK(ym.year() == etl::chrono::year(1995));
        CHECK(ym.month() == etl::chrono::month(5));
    }
    {
        auto const ym = etl::chrono::year_month{etl::chrono::year(1995), etl::chrono::month(13)};
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
        auto const birthday  = etl::chrono::year_month{etl::chrono::year(1995), etl::chrono::month(5)};
        auto const christmas = etl::chrono::year_month{etl::chrono::year(1995), etl::chrono::month(12)};
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
    CHECK(test_year_month());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
