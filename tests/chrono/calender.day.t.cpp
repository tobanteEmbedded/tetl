// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/chrono.hpp>
    #include <etl/cstdint.hpp>
    #include <etl/type_traits.hpp>
#endif

namespace chrono = etl::chrono;

[[nodiscard]] static constexpr auto test_duration() -> bool
{
    CHECK(chrono::days(1) == chrono::hours(24));
    CHECK(chrono::days(2) == chrono::hours(48));
    CHECK(chrono::days(7) == chrono::weeks(1));
    CHECK(chrono::days(14) == chrono::weeks(2));
    return true;
}

[[nodiscard]] static constexpr auto test_day() -> bool
{
    using namespace etl::chrono_literals;

    // traits
    CHECK(etl::is_trivially_default_constructible_v<chrono::day>);

    // construct
    auto d = chrono::day{};
    CHECK_FALSE(d.ok());
    CHECK(static_cast<unsigned>(d) == 0U);

    // inc/dec
    ++d;
    CHECK(d == 1_d);

    d++;
    CHECK(d == 2_d);

    --d;
    CHECK(d == 1_d);

    d--;
    CHECK(d == 0_d);

    // ok
    CHECK(chrono::day(1).ok());
    CHECK(chrono::day(2).ok());
    CHECK(chrono::day(30).ok());
    CHECK(chrono::day(31).ok());
    CHECK_FALSE(chrono::day(0).ok());
    CHECK_FALSE(chrono::day(32).ok());

    // arithmetic
    CHECK(1_d + chrono::days(3) == 4_d);
    CHECK(chrono::days(5) + 1_d == 6_d);

    CHECK(7_d - chrono::days(3) == 4_d);
    CHECK(7_d - 4_d == chrono::days(3));

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

[[nodiscard]] static constexpr auto test_weekday() -> bool
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

[[nodiscard]] static constexpr auto test_weekday_indexed() -> bool
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

[[nodiscard]] static constexpr auto test_weekday_last() -> bool
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

[[nodiscard]] static constexpr auto test_all() -> bool
{
    CHECK(test_duration());
    CHECK(test_day());
    CHECK(test_weekday());
    CHECK(test_weekday_indexed());
    CHECK(test_weekday_last());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
