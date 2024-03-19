// SPDX-License-Identifier: BSL-1.0

#include <etl/format.hpp>

#include <etl/iterator.hpp>
#include <etl/string.hpp>
#include <etl/string_view.hpp>

#include "testing/testing.hpp"

using namespace etl::string_view_literals;

template <typename T>
constexpr auto test() -> bool
{
    // {
    //     using string_t = T;

    // auto str       = string_t();
    // auto ctx       = etl::format_context { etl::back_inserter(str) };
    // auto formatter = etl::formatter<char, char> {};

    // formatter.format('a', ctx);
    // assert(str[0] == 'a');

    // formatter.format('x', ctx);
    // assert(str[1] == 'x');

    // formatter.format('1', ctx);
    // assert(str[2] == '1');
    // }
    // {
    // using string_t = T;

    // auto str = string_t();
    // auto ctx = etl::format_context { etl::back_inserter(str) };

    // auto f1 = etl::formatter<char[sizeof("abc")], char> {};
    // f1.format("abc", ctx);
    // assert(etl::string_view(str.data()) == etl::string_view("abc"));

    // str.clear();
    // auto f2 = etl::formatter<char[sizeof("foobar")], char> {};
    // f2.format("foobar", ctx);
    // assert(etl::string_view(str.data()) == etl::string_view("foobar"));
    // }
    // {
    // using string_t = T;

    // auto str       = string_t();
    // auto ctx       = etl::format_context { etl::back_inserter(str) };
    // auto formatter = etl::formatter<char const*, char> {};

    // auto const* cStr1 = "test";
    // formatter.format(cStr1, ctx);
    // assert(etl::string_view(str.data()) == etl::string_view(cStr1));

    // str.clear();
    // auto const* cStr2 = "abcdef";
    // formatter.format(cStr2, ctx);
    // assert(etl::string_view(str.data()) == etl::string_view(cStr2));
    // }
    // {
    // using string_t = T;

    // auto str       = string_t();
    // auto ctx       = etl::format_context { etl::back_inserter(str) };
    // auto formatter = etl::formatter<etl::string_view, char> {};

    // etl::string_view str1 = "test";
    // formatter.format(str1, ctx);
    // assert(etl::string_view(str.data()) == etl::string_view(str1));

    // str.clear();
    // etl::string_view str2 = "abcdef";
    // formatter.format(str2, ctx);
    // assert(etl::string_view(str.data()) == etl::string_view(str2));
    // }
    // {
    // using string_t = T;

    // auto str       = string_t();
    // auto ctx       = etl::format_context { etl::back_inserter(str) };
    // auto formatter = etl::formatter<string_t, char> {};

    // string_t str1 = "test";
    // formatter.format(str1, ctx);
    // assert(etl::string_view(str.data()) == etl::string_view(str1));

    // str.clear();
    // string_t str2 = "abcdef";
    // formatter.format(str2, ctx);
    // assert(etl::string_view(str.data()) == etl::string_view(str2));
    // }
    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::static_string<24>>());
    assert(test<etl::static_string<55>>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());

    return 0;
}
