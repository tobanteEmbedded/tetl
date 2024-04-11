// SPDX-License-Identifier: BSL-1.0

#include <etl/string.hpp>

#include <etl/algorithm.hpp>
#include <etl/string_view.hpp>
#include <etl/utility.hpp>

#include "testing/testing.hpp"

using namespace etl::string_view_literals;

template <typename String>
[[nodiscard]] constexpr auto test() -> bool
{

    // push_back
    {
        String str{""};
        str.push_back('a');
        str.push_back('b');
        CHECK(str == "ab");
    }

    // pop_back
    {
        String str{"abc"};
        str.pop_back();
        str.pop_back();
        CHECK(str == "a");
    }

    // insert
    {
        auto str = String();
        str.insert(0, 4, 'a');
        CHECK(str == "aaaa"_sv);
    }

    {
        auto str = String("bar");
        str.insert(0, String("foo"));
        CHECK(str == "foobar");
    }

    {
        auto str = String("bar");
        str.insert(1, String("foo"), 1);
        CHECK(str == "booar");
    }

    {
        auto str = String("bar");
        str.insert(0, "foo"_sv);
        CHECK(str == "foobar");
    }

    {
        auto str = String("bar");
        str.insert(1, "foo"_sv, 1);
        CHECK(str == "booar");
    }

    {
        auto str = String("test");
        str.insert(0, 2, 'a');
        CHECK(str == "aatest");

        str = String("tes");
        str.insert(1, 2, 'a');
        str.insert(0, 1, 'b');
        CHECK(str == "btaaes");

        str = String("test");
        str.insert(str.size(), 2, 'a');
        CHECK(str == "testaa");
    }

    {
        auto str = String("");
        str.insert(0, str.capacity(), 'a');
        CHECK(str.size() == str.capacity());
        CHECK(etl::all_of(begin(str), end(str), [](auto ch) { return ch == 'a'; }));
    }

    {
        auto str = String();
        str.insert(0, "aaaa");
        CHECK(str == "aaaa");
    }

    {
        auto str = String("test");
        str.insert(0, "abc");
        CHECK(str == "abctest");

        str = String("tes");
        str.insert(1, "aa");
        str.insert(0, "b");
        CHECK(str == "btaaes");

        str = String("test");
        str.insert(str.size(), "aa");
        CHECK(str == "testaa");
    }

    {
        auto str = String("");
        for (etl::size_t i = 0; i < str.capacity(); ++i) {
            str.insert(0, "a");
        }

        CHECK(str.full());
        CHECK(etl::all_of(begin(str), end(str), [](auto ch) { return ch == 'a'; }));
    }

    {
        auto str = String();
        str.insert(0, "aaaa", 4);
        CHECK(str == "aaaa"_sv);
    }

    {
        auto str = String("test");
        str.insert(0, "abcd", 3);
        CHECK(str == "abctest"_sv);

        str = String("test");
        str.insert(1, "aa", 2);
        str.insert(0, "b", 1);
        CHECK(str == "btaaest"_sv);

        str = String("test");
        str.insert(str.size(), "aa", 1);
        CHECK(str == "testa"_sv);
    }

    {
        auto str = String("");
        for (etl::size_t i = 0; i < str.capacity(); ++i) {
            str.insert(0, "ab", 1);
        }

        CHECK(str.full());
        CHECK(etl::all_of(begin(str), end(str), [](auto ch) { return ch == 'a'; }));
    }

    // erase
    {
        String str = "foo bar";

        // Erase "This "
        str.erase(0, 1);
        CHECK(str == "oo bar"_sv);

        // Erase ' '
        CHECK(*str.erase(etl::find(begin(str), end(str), ' ')) == 'b');
        CHECK(str == "oobar"_sv);

        // Trim from ' ' to the end of the String
        str.erase(str.find('r'));
        CHECK(str == "ooba"_sv);
    }

    // replace
    {
        auto s = String("0123456");
        CHECK(s.replace(0, 2, String("xx")) == "xx23456"_sv);
        CHECK(s.replace(2, 1, String("xx")) == "xxx3456"_sv);
        CHECK(s.replace(begin(s) + 3, begin(s) + 4, String("x")) == "xxxx456"_sv);
    }

    {
        auto s = String("0123456");
        CHECK(s.replace(0, 2, String("xx"), 0) == "xx23456"_sv);
        CHECK(s.replace(2, 1, String("xx"), 0) == "xxx3456"_sv);
    }

    return true;
}

[[nodiscard]] constexpr auto test_all() -> bool
{
    CHECK(test<etl::inplace_string<7>>());
    CHECK(test<etl::inplace_string<18>>());
    CHECK(test<etl::inplace_string<22>>());
    CHECK(test<etl::inplace_string<31>>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
