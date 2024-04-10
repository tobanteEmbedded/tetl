// SPDX-License-Identifier: BSL-1.0

#include <etl/string_view.hpp>

#include <etl/string.hpp>
#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

constexpr auto test() -> bool
{
    using namespace etl::literals;

    // compare
    {
        auto lhs = etl::string_view();
        auto rhs = etl::string_view();

        CHECK(lhs.compare(rhs) == 0);
        CHECK(rhs.compare(lhs) == 0);
    }

    {
        auto const lhs = "test"_sv;
        auto const rhs = "test"_sv;

        CHECK(lhs.compare("test") == 0);
        CHECK(lhs.compare("test"_sv) == 0);
        CHECK(lhs.compare(rhs) == 0);
        CHECK(rhs.compare(lhs) == 0);

        CHECK(lhs.compare(1, 1, "test") < 0);
        CHECK(lhs.compare(1, 1, "test"_sv) < 0);
        CHECK(lhs.compare(1, 1, rhs) < 0);
        CHECK(rhs.compare(1, 1, lhs) < 0);

        CHECK(lhs.compare(1, 1, rhs, 1, 1) == 0);
        CHECK(rhs.compare(1, 1, lhs, 1, 1) == 0);

        CHECK("te"_sv.compare(0, 2, "test"_sv, 0, 2) == 0);
        CHECK("abcabc"_sv.compare(3, 3, "abc"_sv, 0, 3) == 0);
        CHECK("abcabc"_sv.compare(3, 1, "abc"_sv, 0, 3) < 0);
        CHECK("abcabc"_sv.compare(3, 3, "abc"_sv, 0, 1) > 0);

        CHECK("abcabc"_sv.compare(3, 3, "abc", 3) == 0);
        CHECK("abcabc"_sv.compare(3, 1, "abc", 0, 3) < 0);
        CHECK("abcabc"_sv.compare(3, 3, "abc", 0, 1) > 0);
    }

    {
        auto const lhs = "test"_sv;
        auto const rhs = "te"_sv;

        CHECK(lhs.compare(rhs) > 0);
        CHECK(rhs.compare("test"_sv) < 0);
    }

    // operator==
    {
        CHECK("foo"_sv == "foo"_sv);
        CHECK("bar"_sv == "bar"_sv);

        CHECK_FALSE("foo"_sv == etl::inplace_string<16>{"baz"});
        CHECK("bar"_sv == etl::inplace_string<16>{"bar"});

        CHECK(etl::inplace_string<16>{"bar"} == "bar"_sv);
        CHECK_FALSE(etl::inplace_string<16>{"baz"} == "foo"_sv);

        CHECK_FALSE("foo"_sv == "test"_sv);
        CHECK_FALSE("test"_sv == "foo"_sv);
    }

    // operator!=
    {
        CHECK_FALSE("foo"_sv != "foo"_sv);
        CHECK_FALSE("bar"_sv != "bar"_sv);

        CHECK("foo"_sv != etl::inplace_string<16>{"baz"});
        CHECK_FALSE("bar"_sv != etl::inplace_string<16>{"bar"});

        CHECK_FALSE(etl::inplace_string<16>{"bar"} != "bar"_sv);
        CHECK(etl::inplace_string<16>{"baz"} != "foo"_sv);

        CHECK("foo"_sv != "test"_sv);
        CHECK("test"_sv != "foo"_sv);
    }

    // operator<
    {
        auto const test = etl::inplace_string<16>{"test"};
        CHECK_FALSE("test"_sv < "test"_sv);
        CHECK("" < "test"_sv);
        CHECK("test"_sv.substr(0, 1) < "test"_sv);
        CHECK("abc"_sv < "test"_sv);
        CHECK_FALSE("test"_sv < test);
        CHECK_FALSE(test < "test"_sv);
        CHECK_FALSE(test < "abc"_sv);
    }

    // operator<=
    {
        auto const test = etl::inplace_string<16>{"test"};
        CHECK("test"_sv <= test);
        CHECK(test <= "test"_sv);
        CHECK("test"_sv <= "test"_sv);
        CHECK("" <= "test"_sv);
        CHECK("test"_sv.substr(0, 1) <= "test"_sv);
        CHECK("abc"_sv <= "test"_sv);
        CHECK("abc"_sv <= test);
        CHECK_FALSE("test"_sv <= "abc"_sv);
        CHECK_FALSE(test <= "abc"_sv);
    }

    // operator>
    {
        auto const sv   = "test"_sv;
        auto const test = etl::inplace_string<16>{"test"};
        CHECK_FALSE(sv > sv);
        CHECK_FALSE(sv > test);
        CHECK_FALSE(test > sv);
        CHECK("xxxxxx" > sv);
        CHECK(sv > sv.substr(0, 1));
        CHECK(sv > "abc"_sv);

        CHECK_FALSE(sv > "xxxxxx");
        CHECK_FALSE(sv.substr(0, 1) > sv);
        CHECK_FALSE("abc" > sv);
    }

    // operator>=
    {
        auto const sv   = "test"_sv;
        auto const test = etl::inplace_string<16>{"test"};
        CHECK(sv >= sv);
        CHECK(sv >= test);
        CHECK(test >= sv);
        CHECK("xxxxxx" >= sv);
        CHECK(sv >= sv.substr(0, 1));
        CHECK(sv >= "abc");
    }

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
