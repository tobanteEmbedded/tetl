// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/format.hpp>
    #include <etl/iterator.hpp>
    #include <etl/string.hpp>
    #include <etl/string_view.hpp>
#endif

using namespace etl::string_view_literals;

template <typename T>
static constexpr auto test() -> bool
{
    // {
    //     using string_t = T;

    // auto str       = string_t();
    // auto ctx       = etl::format_context { etl::back_inserter(str) };
    // auto formatter = etl::formatter<char, char> {};

    // formatter.format('a', ctx);
    // CHECK(str[0] == 'a');

    // formatter.format('x', ctx);
    // CHECK(str[1] == 'x');

    // formatter.format('1', ctx);
    // CHECK(str[2] == '1');
    // }
    // {
    // using string_t = T;

    // auto str = string_t();
    // auto ctx = etl::format_context { etl::back_inserter(str) };

    // auto f1 = etl::formatter<char[sizeof("abc")], char> {};
    // f1.format("abc", ctx);
    // CHECK(etl::string_view(str.data()) == etl::string_view("abc"));

    // str.clear();
    // auto f2 = etl::formatter<char[sizeof("foobar")], char> {};
    // f2.format("foobar", ctx);
    // CHECK(etl::string_view(str.data()) == etl::string_view("foobar"));
    // }
    // {
    // using string_t = T;

    // auto str       = string_t();
    // auto ctx       = etl::format_context { etl::back_inserter(str) };
    // auto formatter = etl::formatter<char const*, char> {};

    // auto const* cStr1 = "test";
    // formatter.format(cStr1, ctx);
    // CHECK(etl::string_view(str.data()) == etl::string_view(cStr1));

    // str.clear();
    // auto const* cStr2 = "abcdef";
    // formatter.format(cStr2, ctx);
    // CHECK(etl::string_view(str.data()) == etl::string_view(cStr2));
    // }
    // {
    // using string_t = T;

    // auto str       = string_t();
    // auto ctx       = etl::format_context { etl::back_inserter(str) };
    // auto formatter = etl::formatter<etl::string_view, char> {};

    // etl::string_view str1 = "test";
    // formatter.format(str1, ctx);
    // CHECK(etl::string_view(str.data()) == etl::string_view(str1));

    // str.clear();
    // etl::string_view str2 = "abcdef";
    // formatter.format(str2, ctx);
    // CHECK(etl::string_view(str.data()) == etl::string_view(str2));
    // }
    // {
    // using string_t = T;

    // auto str       = string_t();
    // auto ctx       = etl::format_context { etl::back_inserter(str) };
    // auto formatter = etl::formatter<string_t, char> {};

    // string_t str1 = "test";
    // formatter.format(str1, ctx);
    // CHECK(etl::string_view(str.data()) == etl::string_view(str1));

    // str.clear();
    // string_t str2 = "abcdef";
    // formatter.format(str2, ctx);
    // CHECK(etl::string_view(str.data()) == etl::string_view(str2));
    // }
    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test<etl::inplace_string<24>>());
    CHECK(test<etl::inplace_string<55>>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());

    return 0;
}
