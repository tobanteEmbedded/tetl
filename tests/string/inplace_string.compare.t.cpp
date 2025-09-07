// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/algorithm.hpp>
    #include <etl/cstddef.hpp>
    #include <etl/iterator.hpp>
    #include <etl/string.hpp>
    #include <etl/string_view.hpp>
    #include <etl/utility.hpp>
#endif

using namespace etl::string_view_literals;

template <typename String>
[[nodiscard]] static constexpr auto test() -> bool
{
    // compare
    {
        auto lhs = String();
        auto rhs = String();

        CHECK(lhs.compare(rhs) == 0);
        CHECK(rhs.compare(lhs) == 0);
    }

    {
        auto lhs = String();
        auto rhs = etl::inplace_string<2>{};

        CHECK(lhs.compare(rhs) == 0);
        CHECK(rhs.compare(lhs) == 0);
    }

    {
        auto const lhs = String("test");
        auto const rhs = String("test");

        CHECK(lhs.compare("test") == 0);
        CHECK(lhs.compare("test"_sv) == 0);
        CHECK(lhs.compare("test1"_sv) == -1);
        CHECK(lhs.compare("tes"_sv) == +1);
        CHECK(lhs.compare(rhs) == 0);
        CHECK(rhs.compare(lhs) == 0);

        CHECK(lhs.compare(1, 1, "test") < 0);
        CHECK(lhs.compare(1, 1, "test"_sv) < 0);
        CHECK(lhs.compare(1, 1, rhs) < 0);
        CHECK(rhs.compare(1, 1, lhs) < 0);

        CHECK(lhs.compare(1, 1, rhs, 1, 1) == 0);
        CHECK(rhs.compare(1, 1, lhs, 1, 1) == 0);

        CHECK(String("te").compare(0, 2, "test"_sv, 0, 2) == 0);
        CHECK(String("abcabc").compare(3, 3, "abc"_sv, 0, 3) == 0);
        CHECK(String("abcabc").compare(3, 1, "abc"_sv, 0, 3) < 0);
        CHECK(String("abcabc").compare(3, 3, "abc"_sv, 0, 1) > 0);

        CHECK(String("abcabc").compare(3, 3, "abc", 3) == 0);
        CHECK(String("abcabc").compare(3, 1, "abc", 0, 3) < 0);
        CHECK(String("abcabc").compare(3, 3, "abc", 0, 1) > 0);
    }

    {
        auto const lhs = String("test");
        auto const rhs = String("te");

        CHECK(lhs.compare(rhs) > 0);
        CHECK(rhs.compare("test"_sv) < 0);

        auto other = etl::inplace_string<9>{"te"};
        CHECK(lhs.compare(other) > 0);
        CHECK(other.compare(etl::string_view("te")) == 0);
    }

    // operator==
    CHECK(String("foo") == String("foo"));
    CHECK(String("foo") == "foo");
    CHECK("foo" == String("foo"));

    CHECK_FALSE(String("foo") == String("bar"));
    CHECK_FALSE(String("foo") == "bar");
    CHECK_FALSE("foo" == String("bar"));

    // operator!=
    CHECK(String("foo") != String("bar"));
    CHECK(String("foo") != "bar");
    CHECK("foo" != String("bar"));

    CHECK_FALSE(String("foo") != String("foo"));
    CHECK_FALSE(String("foo") != "foo");
    CHECK_FALSE("foo" != String("foo"));

    // operator<
    CHECK_FALSE(String("foo") < String("bar"));
    CHECK_FALSE(String("foo") < "bar");
    CHECK_FALSE("foo" < String("bar"));

    CHECK_FALSE(String("foo") < String("foo"));
    CHECK_FALSE(String("foo") < "foo");
    CHECK_FALSE("foo" < String("foo"));

    // operator<=
    CHECK_FALSE(String("foo") <= String("bar"));
    CHECK_FALSE(String("foo") <= "bar");
    CHECK_FALSE("foo" <= String("bar"));

    CHECK(String("foo") <= String("foo"));
    CHECK(String("foo") <= "foo");
    CHECK("foo" <= String("foo"));

    // operator>
    CHECK(String("foo") > String("bar"));
    CHECK(String("foo") > "bar");
    CHECK("foo" > String("bar"));

    CHECK_FALSE(String("foo") > String("foo"));
    CHECK_FALSE(String("foo") > "foo");
    CHECK_FALSE("foo" > String("foo"));

    // operator>=
    CHECK(String("foo") >= String("bar"));
    CHECK(String("foo") >= "bar");
    CHECK("foo" >= String("bar"));

    CHECK(String("foo") >= String("foo"));
    CHECK(String("foo") >= "foo");
    CHECK("foo" >= String("foo"));

    return true;
}

[[nodiscard]] static constexpr auto test_all() -> bool
{
    CHECK(test<etl::inplace_string<7>>());
    CHECK(test<etl::inplace_string<15>>());
    CHECK(test<etl::inplace_string<32>>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
