// SPDX-License-Identifier: BSL-1.0

#include <etl/chrono.hpp>

#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

namespace chrono = etl::chrono;

[[nodiscard]] constexpr static auto test_month() -> bool
{
    // traits
    CHECK(etl::is_trivially_default_constructible_v<chrono::month>);

    // construct
    auto m = chrono::month{};
    CHECK(static_cast<unsigned>(m) == 0U);
    CHECK_FALSE(m.ok());

    // ok
    CHECK(chrono::month(1).ok());
    CHECK(chrono::month(2).ok());
    CHECK(chrono::month(11).ok());
    CHECK(chrono::month(12).ok());
    CHECK_FALSE(chrono::month(0).ok());
    CHECK_FALSE(chrono::month(13).ok());

    // inc/dec
    ++m;
    CHECK(m == chrono::month(1));

    m++;
    CHECK(m == chrono::month(2));

    --m;
    CHECK(m == chrono::month(1));

    m--;
    CHECK(m == chrono::month(12));

    m += chrono::months(2);
    CHECK(m == chrono::February);

    m -= chrono::months(2);
    CHECK(m == chrono::December);

    // arithmetic
    CHECK(chrono::month(1) + chrono::months(1) == chrono::month(2));
    CHECK(chrono::month(12) + chrono::months(1) == chrono::month(1));
    CHECK(chrono::December + chrono::months(2) == chrono::February);
    CHECK(chrono::December + chrono::months(12) == chrono::December);
    CHECK(chrono::December + chrono::months(13) == chrono::January);
    CHECK(chrono::months(1) + chrono::month(1) == chrono::month(2));

    CHECK(chrono::December - chrono::months(2) == chrono::October);
    CHECK(chrono::December - chrono::months(12) == chrono::December);
    CHECK(chrono::December - chrono::months(13) == chrono::November);

    CHECK(chrono::January - chrono::January == chrono::months(0));
    CHECK(chrono::January - chrono::December == chrono::months(1));
    CHECK(chrono::January - chrono::November == chrono::months(2));
    CHECK(chrono::January - chrono::October == chrono::months(3));

    CHECK(chrono::December - chrono::December == chrono::months(0));
    CHECK(chrono::December - chrono::November == chrono::months(1));
    CHECK(chrono::December - chrono::October == chrono::months(2));
    CHECK(chrono::December - chrono::January == chrono::months(11));

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

[[nodiscard]] constexpr static auto test_month_day() -> bool
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

[[nodiscard]] constexpr static auto test_month_day_last() -> bool
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

[[nodiscard]] constexpr static auto test_month_weekday() -> bool
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

[[nodiscard]] constexpr static auto test_month_weekday_last() -> bool
{
    // traits
    CHECK(etl::is_nothrow_constructible_v<chrono::month_weekday_last, chrono::month, chrono::weekday_last>);

    {
        auto const mwdl = chrono::month_weekday_last{chrono::January, chrono::Sunday[chrono::last]};
        CHECK_NOEXCEPT(mwdl.weekday_last());
        CHECK_NOEXCEPT(mwdl.month());
        CHECK_NOEXCEPT(mwdl.ok());
    }

    // construct
    {
        auto const mwdl = chrono::month_weekday_last{chrono::January, chrono::Sunday[chrono::last]};
        CHECK(mwdl.ok());
        CHECK(mwdl.month() == chrono::January);
        CHECK(mwdl.weekday_last() == chrono::Sunday[chrono::last]);
    }

    {
        auto const mwdl = chrono::May / chrono::Monday[chrono::last];
        CHECK(mwdl.ok());
        CHECK(mwdl.month() == chrono::May);
        CHECK(mwdl.weekday_last() == chrono::Monday[chrono::last]);
    }

    {
        auto const mwdl = chrono::Friday[chrono::last] / chrono::April;
        CHECK(mwdl.ok());
        CHECK(mwdl.month() == chrono::April);
        CHECK(mwdl.weekday_last() == chrono::Friday[chrono::last]);
    }

    {
        auto const mwdl = 9 / chrono::Monday[chrono::last];
        CHECK(mwdl.ok());
        CHECK(mwdl.month() == chrono::September);
        CHECK(mwdl.weekday_last() == chrono::Monday[chrono::last]);
    }

    {
        auto const mwdl = chrono::Friday[chrono::last] / 3;
        CHECK(mwdl.ok());
        CHECK(mwdl.month() == chrono::March);
        CHECK(mwdl.weekday_last() == chrono::Friday[chrono::last]);
    }

    // compare
    {
        CHECK((chrono::Friday[chrono::last] / 3) == (chrono::Friday[chrono::last] / 3));
        CHECK((chrono::Friday[chrono::last] / 4) != (chrono::Friday[chrono::last] / 3));
        CHECK((chrono::Sunday[chrono::last] / 3) != (chrono::Friday[chrono::last] / 3));
    }

    return true;
}

[[nodiscard]] constexpr static auto test_all() -> bool
{
    CHECK(test_month());
    CHECK(test_month_day());
    CHECK(test_month_day_last());
    CHECK(test_month_weekday());
    CHECK(test_month_weekday_last());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
