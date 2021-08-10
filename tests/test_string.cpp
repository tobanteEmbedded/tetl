// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#include "etl/string.hpp"

#include "etl/algorithm.hpp"   // for for_each
#include "etl/cstddef.hpp"     // for size_t
#include "etl/iterator.hpp"    // for begin, end, rb...
#include "etl/string_view.hpp" // for string_view
#include "etl/utility.hpp"     // for as_const

#include "catch2/catch_template_test_macros.hpp"
#include "catch2/generators/catch_generators.hpp"

using namespace etl::literals;
using namespace Catch::Generators;

TEST_CASE("string/char_traits: <char>::length", "[string]")
{
    auto [input, expected] = GENERATE(table<char const*, etl::size_t>({
        { "", 0 },
        { "a", 1 },
        { "ab", 2 },
        { "to", 2 },
        { "abc", 3 },
        { "xxxxxxxxxx", 10 },
        { "xxxxxxxxxxxxxxxxxxxx", 20 },
    }));

    REQUIRE(etl::char_traits<char>::length(input) == expected);
}

TEST_CASE("string/char_traits: <char>::eq", "[string]")
{
    auto [lhs, rhs, expected] = GENERATE(table<char, char, bool>({
        { '0', '0', true },
        { '1', '1', true },
        { '2', '2', true },
        { '3', '3', true },
        { '4', '4', true },
        { '5', '5', true },
        { '6', '6', true },
        { '7', '7', true },
        { '8', '8', true },
        { '9', '9', true },

        { 'a', 'a', true },
        { 'b', 'b', true },
        { 'c', 'c', true },
        { 'd', 'd', true },
        { 'e', 'e', true },
        { 'f', 'f', true },
        { 'g', 'g', true },
        { 'h', 'h', true },
        { 'i', 'i', true },
        { 'j', 'j', true },
        { 'k', 'k', true },
        { 'l', 'l', true },
        { 'm', 'm', true },
        { 'n', 'n', true },
        { 'o', 'o', true },
        { 'p', 'p', true },
        { 'q', 'q', true },
        { 'r', 'r', true },
        { 's', 's', true },
        { 't', 't', true },
        { 'u', 'u', true },
        { 'v', 'v', true },
        { 'w', 'w', true },
        { 'x', 'x', true },
        { 'y', 'y', true },
        { 'z', 'z', true },

        { 'A', 'A', true },
        { 'B', 'B', true },
        { 'C', 'C', true },
        { 'D', 'D', true },
        { 'E', 'E', true },
        { 'F', 'F', true },
        { 'G', 'G', true },
        { 'H', 'H', true },
        { 'I', 'I', true },
        { 'J', 'J', true },
        { 'K', 'K', true },
        { 'L', 'L', true },
        { 'M', 'M', true },
        { 'N', 'N', true },
        { 'O', 'O', true },
        { 'P', 'P', true },
        { 'Q', 'Q', true },
        { 'R', 'R', true },
        { 'S', 'S', true },
        { 'T', 'T', true },
        { 'U', 'U', true },
        { 'V', 'V', true },
        { 'W', 'W', true },
        { 'X', 'X', true },
        { 'Y', 'Y', true },
        { 'Z', 'Z', true },

        { 'a', 'b', false },
        { 'b', 'a', false },
        { '1', '2', false },
        { '2', '1', false },
        { 'a', '3', false },
        { '3', 'a', false },
        { 'a', 'A', false },
        { 'b', 'B', false },
    }));

    REQUIRE(etl::char_traits<char>::eq(lhs, rhs) == expected);
}

TEST_CASE("string/char_traits: <char>::lt", "[string]")
{
    auto [lhs, rhs, expected] = GENERATE(table<char, char, bool>({
        { '0', '0', false },
        { '1', '1', false },
        { '2', '2', false },
        { '3', '3', false },
        { '4', '4', false },
        { '5', '5', false },
        { '6', '6', false },
        { '7', '7', false },
        { '8', '8', false },
        { '9', '9', false },

        { 'a', 'a', false },
        { 'b', 'b', false },
        { 'c', 'c', false },
        { 'd', 'd', false },
        { 'e', 'e', false },
        { 'f', 'f', false },
        { 'g', 'g', false },
        { 'h', 'h', false },
        { 'i', 'i', false },
        { 'j', 'j', false },
        { 'k', 'k', false },
        { 'l', 'l', false },
        { 'm', 'm', false },
        { 'n', 'n', false },
        { 'o', 'o', false },
        { 'p', 'p', false },
        { 'q', 'q', false },
        { 'r', 'r', false },
        { 's', 's', false },
        { 't', 't', false },
        { 'u', 'u', false },
        { 'v', 'v', false },
        { 'w', 'w', false },
        { 'x', 'x', false },
        { 'y', 'y', false },
        { 'z', 'z', false },

        { 'A', 'A', false },
        { 'B', 'B', false },
        { 'C', 'C', false },
        { 'D', 'D', false },
        { 'E', 'E', false },
        { 'F', 'F', false },
        { 'G', 'G', false },
        { 'H', 'H', false },
        { 'I', 'I', false },
        { 'J', 'J', false },
        { 'K', 'K', false },
        { 'L', 'L', false },
        { 'M', 'M', false },
        { 'N', 'N', false },
        { 'O', 'O', false },
        { 'P', 'P', false },
        { 'Q', 'Q', false },
        { 'R', 'R', false },
        { 'S', 'S', false },
        { 'T', 'T', false },
        { 'U', 'U', false },
        { 'V', 'V', false },
        { 'W', 'W', false },
        { 'X', 'X', false },
        { 'Y', 'Y', false },
        { 'Z', 'Z', false },

        { 'a', 'A', false },
        { '2', '1', false },
        { 'b', 'a', false },
        { 'a', '3', false },

        { 'a', 'b', true },
        { '1', '2', true },
        { '3', 'a', true },

    }));

    REQUIRE(etl::char_traits<char>::lt(lhs, rhs) == expected);
}

TEST_CASE("string/char_traits: <char>::assign(char,char)", "[string]")
{
    auto [ch] = GENERATE(table<char>({
        { '0' },
        { '1' },
        { '2' },
        { '3' },
        { '4' },
        { '5' },
        { '6' },
        { '7' },
        { '8' },
        { '9' },

        { 'a' },
        { 'b' },
        { 'c' },
        { 'd' },
        { 'e' },
        { 'f' },
        { 'g' },
        { 'h' },
        { 'i' },
        { 'j' },
        { 'k' },
        { 'l' },
        { 'm' },
        { 'n' },
        { 'o' },
        { 'p' },
        { 'q' },
        { 'r' },
        { 's' },
        { 't' },
        { 'u' },
        { 'v' },
        { 'w' },
        { 'x' },
        { 'y' },
        { 'z' },

        { 'A' },
        { 'B' },
        { 'C' },
        { 'D' },
        { 'E' },
        { 'F' },
        { 'G' },
        { 'H' },
        { 'I' },
        { 'J' },
        { 'K' },
        { 'L' },
        { 'M' },
        { 'N' },
        { 'O' },
        { 'P' },
        { 'Q' },
        { 'R' },
        { 'S' },
        { 'T' },
        { 'U' },
        { 'V' },
        { 'W' },
        { 'X' },
        { 'Y' },
        { 'Z' },

    }));

    char other {};
    etl::char_traits<char>::assign(other, ch);
    REQUIRE(other == ch);
}

TEMPLATE_TEST_CASE("string: static_string()", "[string]",
    etl::static_string<12>, etl::static_string<32>,
    etl::static_string<12> const, etl::static_string<32> const)
{
    TestType str {};

    CHECK_FALSE(str.full());
    CHECK(str.empty());
    CHECK(str.capacity() == str.max_size());
    CHECK(str.size() == etl::size_t(0));
    CHECK(str.length() == etl::size_t(0));
}

TEMPLATE_TEST_CASE("string: static_string(size_t,char)", "[string]",
    etl::static_string<24>, etl::static_string<32>,
    etl::static_string<24> const, etl::static_string<32> const)
{
    using string_t = TestType;

    auto [size, character] = GENERATE(table<etl::size_t, char>({
        { 1, 'x' },
        { 2, 'x' },
        { 2, 'x' },
        { 3, 'x' },
        { 10, 'x' },
        { 20, 'x' },
    }));

    auto str = string_t { size, character };

    CHECK_FALSE(str.empty());
    CHECK_FALSE(str.full());

    CHECK(str.size() == size);
    CHECK(str.size() == etl::strlen(str.c_str()));
    CHECK(etl::all_of(
        begin(str), end(str), [ch = character](auto c) { return c == ch; }));
}

TEMPLATE_TEST_CASE("string: static_string(char const*)", "[string]",
    etl::static_string<12>, etl::static_string<32>,
    etl::static_string<12> const, etl::static_string<32> const)
{
    auto [input, size] = GENERATE(table<char const*, etl::size_t>({
        { "", 0 },
        { "a", 1 },
        { "ab", 2 },
        { "to", 2 },
        { "abc", 3 },
        { "foo_bar", 7 },
        { "foo bar", 7 },
        { "foo?bar", 7 },
        { "foo\nbar", 7 },
        { "xxxxxxxxxx", 10 },
    }));

    TestType str { input };

    CHECK_FALSE(str.full());

    CHECK(str.capacity() == str.max_size());
    CHECK(etl::strlen(str.data()) == size);
    CHECK(str.size() == size);
    CHECK(str.length() == size);
    CHECK(str == etl::string_view { input });
}

TEMPLATE_TEST_CASE("string: static_string(char const*, size_t)", "[string]",
    etl::static_string<12>, etl::static_string<32>,
    etl::static_string<12> const, etl::static_string<32> const)
{
    auto [input, size] = GENERATE(table<char const*, etl::size_t>({
        { "a", 1 },
        { "ab", 2 },
        { "to", 2 },
        { "abc", 3 },
        { "foo_bar", 7 },
        { "foo bar", 7 },
        { "foo?bar", 7 },
        { "foo\nbar", 7 },
        { "xxxxxxxxxx", 10 },
    }));

    TestType str { input, size };

    CHECK_FALSE(str.full());
    CHECK_FALSE(str.empty());

    CHECK(etl::strlen(str.data()) == size);
    CHECK(str.capacity() == str.max_size());
    CHECK(str.size() == size);
    CHECK(str.length() == size);
    CHECK(str == etl::string_view { input });
}

TEMPLATE_TEST_CASE("string: static_string(first,last)", "[string]",
    etl::static_string<12>, etl::static_string<32>,
    etl::static_string<12> const, etl::static_string<32> const)
{
    auto [input, size] = GENERATE(table<char const*, etl::size_t>({
        { "a", 1 },
        { "ab", 2 },
        { "to", 2 },
        { "abc", 3 },
        { "foo_bar", 7 },
        { "foo bar", 7 },
        { "foo?bar", 7 },
        { "foo\nbar", 7 },
        { "xxxxxxxxxx", 10 },
    }));

    auto str = TestType { input, etl::next(input, size) };

    CHECK(str.size() == size);
    CHECK(etl::strlen(str.c_str()) == size);
    CHECK(str == etl::string_view { input });
    CHECK_FALSE(str.full());
}

TEMPLATE_TEST_CASE("string: static_string(string,pos)", "[string]",
    etl::static_string<12>, etl::static_string<32>,
    etl::static_string<12> const, etl::static_string<32> const)
{
    using etl::size_t;
    using etl::string_view;

    auto [in, pos, expected]
        = GENERATE(table<char const*, size_t, string_view>({
            { "0123456789", 0, "0123456789"_sv },
            { "0123456789", 4, "456789"_sv },
            { "0123456789", 9, "9"_sv },

            { "testabc", 0, "testabc"_sv },
            { "testabc", 4, "abc"_sv },
            { "testabc", 9, ""_sv },
        }));

    TestType src { in };
    TestType destination(src, pos);
    CHECK(destination == expected);
}

TEMPLATE_TEST_CASE("string: static_string(string,pos,count)", "[string]",
    etl::static_string<12>, etl::static_string<32>,
    etl::static_string<12> const, etl::static_string<32> const)
{
    TestType src { "testabc" };

    TestType dest1(src, 0, 2);
    CHECK(dest1 == "te"_sv);

    TestType dest2(src, 4, 2);
    CHECK(dest2 == "ab"_sv);

    auto dest3 = TestType(src, 9, 2);
    CHECK(dest3 == ""_sv);
}

TEMPLATE_TEST_CASE("string: static_string(string_view)", "[string]",
    etl::static_string<12>, etl::static_string<32>,
    etl::static_string<12> const, etl::static_string<32> const)
{
    etl::string_view sv { "test" };
    TestType dest { sv };

    CHECK_FALSE(dest.full());
    CHECK(dest.size() == etl::size_t(4));
    CHECK(dest.length() == etl::size_t(4));
    CHECK(dest[0] == 't');
    CHECK(dest[1] == 'e');
    CHECK(dest[2] == 's');
    CHECK(dest[3] == 't');
}

TEMPLATE_TEST_CASE("string: static_string(string_view,pos,n)", "[string]",
    etl::static_string<12>, etl::static_string<32>,
    etl::static_string<12> const, etl::static_string<32> const)
{
    etl::string_view sv { "test" };
    TestType dest { sv, 2, 2 };

    CHECK_FALSE(dest.full());
    CHECK(dest.size() == etl::size_t(2));
    CHECK(dest.length() == etl::size_t(2));
    CHECK(dest[0] == 's');
    CHECK(dest[1] == 't');
}

TEMPLATE_TEST_CASE("string: static_string::operator=", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    SECTION("string")
    {
        TestType src1 {};
        TestType str1 {};
        str1 = src1;
        CHECK(str1.size() == 0);
        CHECK(str1.empty());

        TestType src2 { "test" };
        TestType str2 {};
        str2 = src2;
        CHECK(str2.size() == 4);
        CHECK(str2 == "test"_sv);

        auto src3 = TestType { "abc" };
        TestType str3;
        str3 = src3;
        CHECK(str3.size() == 3);
        CHECK(str3 == "abc"_sv);
    }

    SECTION("char const*")
    {
        auto const* src2 = "test";
        TestType str2 {};
        str2 = src2;
        CHECK(str2.size() == 4);
        CHECK(str2 == "test"_sv);

        auto const* src3 = "abc";
        TestType str3;
        str3 = src3;
        CHECK(str3.size() == 3);
        CHECK(str3 == "abc"_sv);
    }

    SECTION("char")
    {
        auto const src2 = 'a';
        TestType str2 {};
        str2 = src2;
        CHECK(str2.size() == 1);
        CHECK(str2 == "a"_sv);

        auto const src3 = 'b';
        TestType str3;
        str3 = src3;
        CHECK(str3.size() == 1);
        CHECK(str3 == "b"_sv);
    }

    SECTION("string_view")
    {
        etl::string_view src1 {};
        TestType str1 {};
        str1 = src1;
        CHECK(str1.size() == 0);

        etl::string_view src2 { "test" };
        TestType str2 {};
        str2 = src2;
        CHECK(str2.size() == 4);
        CHECK(str2 == "test"_sv);

        auto src3 = "abc"_sv;
        TestType str3;
        str3 = src3;
        CHECK(str3.size() == 3);
        CHECK(str3 == "abc"_sv);
    }
}

TEMPLATE_TEST_CASE("string: static_string::assign", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    SECTION("string")
    {
        TestType dest {};

        auto const src1 = TestType {};
        dest.assign(src1);
        CHECK(dest.size() == 0);
        CHECK(dest.empty());

        auto const src2 = TestType { "test" };
        dest.assign(src2);
        CHECK(dest.size() == 4);
        CHECK(dest == "test"_sv);

        auto src3 = TestType { "abc" };
        dest.assign(etl::move(src3));
        CHECK(dest.size() == 3);
        CHECK(dest == "abc"_sv);

        auto const src4 = TestType { "abc" };
        dest.assign(src4, 1, 1);
        CHECK(dest.size() == 1);
        CHECK(dest == "b"_sv);
    }

    SECTION("string_view")
    {
        TestType dest {};

        dest.assign(""_sv);
        CHECK(dest.size() == 0);
        CHECK(dest.empty());

        dest.assign("test"_sv);
        CHECK(dest.size() == 4);
        CHECK(dest == "test"_sv);

        dest.assign("abc"_sv);
        CHECK(dest.size() == 3);
        CHECK(dest == "abc"_sv);

        dest.assign("abc"_sv, 0);
        CHECK(dest.size() == 3);
        CHECK(dest == "abc"_sv);

        dest.assign("abc"_sv, 1);
        CHECK(dest.size() == 2);
        CHECK(dest == "bc"_sv);

        dest.assign("abc"_sv, 1, 1);
        CHECK(dest.size() == 1);
        CHECK(dest == "b"_sv);

        auto const src = etl::static_string<8> { "abc" };
        dest.assign(src);
        CHECK(dest.size() == 3);
        CHECK(dest == "abc"_sv);

        dest.assign(src, 1, 1);
        CHECK(dest.size() == 1);
        CHECK(dest == "b"_sv);
    }

    SECTION("first, last")
    {
        TestType dest {};

        auto src1 = "test"_sv;
        dest.assign(begin(src1), end(src1));
        CHECK(dest.size() == 4);
        CHECK(dest == "test"_sv);

        auto src2 = "abc"_sv;
        dest.assign(begin(src2), end(src2) - 1);
        CHECK(dest.size() == 2);
        CHECK(dest == "ab"_sv);
    }

    SECTION("char const*")
    {
        TestType dest {};

        dest.assign("test");
        CHECK(dest.size() == 4);
        CHECK(dest == "test"_sv);

        dest.assign("abc");
        CHECK(dest.size() == 3);
        CHECK(dest == "abc"_sv);
    }

    SECTION("char")
    {
        TestType dest {};

        dest.assign(1, 'a');
        CHECK(dest.size() == 1);
        CHECK(dest == "a"_sv);

        dest.assign(4, 'z');
        CHECK(dest.size() == 4);
        CHECK(dest == "zzzz"_sv);
    }
}

TEMPLATE_TEST_CASE("string: static_string::constexpr", "[string]",
    etl::static_string<8>, etl::static_string<12>, etl::static_string<32>)
{
    constexpr TestType str1 {};

    STATIC_REQUIRE(str1.empty() == true);
    STATIC_REQUIRE(str1.capacity() == str1.max_size());
    STATIC_REQUIRE(str1.size() == 0);
    STATIC_REQUIRE(str1.length() == 0);

    constexpr auto str2 = []() {
        TestType str {};
        // APPEND 4 CHARACTERS
        const char* cptr = "C-string";
        str.append(cptr, 4);
        return str;
    }();

    STATIC_REQUIRE(str2.empty() == false);
    STATIC_REQUIRE(str2.capacity() == str1.max_size());
    STATIC_REQUIRE(etl::strlen(str2.data()) == 4);
    STATIC_REQUIRE(str2.size() == 4);
    STATIC_REQUIRE(str2.length() == 4);
    STATIC_REQUIRE(str2[0] == 'C');
    STATIC_REQUIRE(str2[1] == '-');
    STATIC_REQUIRE(str2[2] == 's');
    STATIC_REQUIRE(str2[3] == 't');
}

TEMPLATE_TEST_CASE("string: static_string::operator[]", "[string]",
    etl::static_string<12>, etl::static_string<32>,
    etl::static_string<12> const, etl::static_string<32> const)
{
    TestType str { "abc" };
    REQUIRE(str[0] == 'a');
    REQUIRE(str[1] == 'b');
    REQUIRE(str[2] == 'c');
}

TEMPLATE_TEST_CASE("string: static_string::begin/end", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    TestType str { "aaa" };

    etl::for_each(
        str.begin(), str.end(), [](auto& c) { REQUIRE(c == char('a')); });
    for (auto const& c : str) { REQUIRE(c == char('a')); };
}

TEMPLATE_TEST_CASE("string: static_string::cbegin/cend", "[string]",
    etl::static_string<12>, etl::static_string<32>,
    etl::static_string<12> const, etl::static_string<32> const)
{
    TestType str { "aaa" };

    etl::for_each(str.cbegin(), str.cend(),
        [](auto const& c) { REQUIRE(c == char('a')); });
}

TEMPLATE_TEST_CASE("string: static_string::rbegin/rend", "[string]",
    etl::static_string<12>, etl::static_string<32>,
    etl::static_string<12> const, etl::static_string<32> const)
{
    TestType empty {};
    CHECK(empty.rbegin() == empty.rend());

    TestType str1 { "test" };
    CHECK(str1.rbegin() != str1.rend());
    auto begin1 = str1.rbegin();
    CHECK(*begin1++ == 't');
    CHECK(*begin1++ == 's');
    CHECK(*begin1++ == 'e');
    CHECK(*begin1++ == 't');
    CHECK(begin1 == str1.rend());
}

TEMPLATE_TEST_CASE("string: static_string::crbegin/crend", "[string]",
    etl::static_string<12>, etl::static_string<32>,
    etl::static_string<12> const, etl::static_string<32> const)
{
    TestType empty {};
    CHECK(empty.crbegin() == empty.crend());

    TestType str1 { "test" };
    CHECK(str1.crbegin() != str1.crend());
    auto begin1 = str1.crbegin();
    CHECK(*begin1++ == 't');
    CHECK(*begin1++ == 's');
    CHECK(*begin1++ == 'e');
    CHECK(*begin1++ == 't');
    CHECK(begin1 == str1.crend());
}

TEMPLATE_TEST_CASE("string: static_string::append(count, CharType)", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    auto str = TestType();
    str.append(4, 'a');

    REQUIRE(str.size() == etl::size_t(4));
    REQUIRE(str.length() == etl::size_t(4));
    REQUIRE(str[0] == 'a');
    REQUIRE(str[1] == 'a');
    REQUIRE(str[2] == 'a');
    REQUIRE(str[3] == 'a');
}

TEMPLATE_TEST_CASE("string: static_string::append(const_pointer, count)",
    "[string]", etl::static_string<8>, etl::static_string<12>,
    etl::static_string<32>)
{
    TestType str {};

    // APPEND 4 CHARACTERS
    const char* cptr = "C-string";
    str.append(cptr, 4);

    REQUIRE(str.empty() == false);
    REQUIRE(str.capacity() == str.max_size());
    REQUIRE(str.size() == etl::size_t(4));
    REQUIRE(str.length() == etl::size_t(4));
    REQUIRE(str[0] == 'C');
    REQUIRE(str[1] == '-');
    REQUIRE(str[2] == 's');
    REQUIRE(str[3] == 't');
}

TEMPLATE_TEST_CASE("string: static_string::append(const_pointer)", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    TestType str {};
    const char* cptr = "C-string";
    str.append(cptr);

    REQUIRE(str.size() == etl::strlen(cptr));
    REQUIRE(str.length() == etl::strlen(cptr));
    REQUIRE(str[0] == 'C');
    REQUIRE(str[1] == '-');
    REQUIRE(str[2] == 's');
    REQUIRE(str[3] == 't');
}

TEMPLATE_TEST_CASE("string: static_string::append(first,last)", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    SECTION("empty")
    {
        etl::string_view emptySrc { "" };

        TestType empty {};
        empty.append(begin(emptySrc), end(emptySrc));
        CHECK(empty.empty());

        TestType str { "abc" };
        str.append(begin(emptySrc), end(emptySrc));
        CHECK(str == "abc"_sv);
    }

    SECTION("no nulls")
    {
        etl::string_view src { "_test" };

        TestType dest { "abc" };
        dest.append(begin(src), end(src));
        CHECK(dest == "abc_test"_sv);
    }
}

TEMPLATE_TEST_CASE("string: static_string::append(string)", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    SECTION("empty")
    {
        TestType emptySrc { "" };

        TestType empty {};
        empty.append(emptySrc);
        CHECK(empty.empty());

        TestType str { "abc" };
        str.append(emptySrc);
        CHECK(str == "abc"_sv);
    }

    SECTION("no nulls")
    {
        TestType src { "_test" };

        TestType dest { "abc" };
        dest.append(src);
        CHECK(dest == "abc_test"_sv);
    }
}

TEMPLATE_TEST_CASE("string: static_string::append(string,pos,count)",
    "[string]", etl::static_string<12>, etl::static_string<32>)
{
    SECTION("empty")
    {
        TestType emptySrc { "" };

        TestType empty {};
        empty.append(emptySrc, 0);
        CHECK(empty.empty());

        TestType str { "abc" };
        str.append(emptySrc, 1);
        CHECK(str == "abc"_sv);
    }

    SECTION("no nulls")
    {
        TestType src { "_test" };

        TestType dest { "abc" };
        dest.append(src, 2, 2);
        CHECK(dest == "abces"_sv);
    }
}

TEMPLATE_TEST_CASE("string: static_string::append(string_view)", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    SECTION("empty")
    {
        etl::string_view emptySrc { "" };

        TestType empty {};
        empty.append(emptySrc);
        CHECK(empty.empty());

        TestType str { "abc" };
        str.append(emptySrc);
        CHECK(str == "abc"_sv);
    }

    SECTION("no nulls")
    {
        etl::string_view src { "_test" };

        TestType dest { "abc" };
        dest.append(src);
        CHECK(dest == "abc_test"_sv);
    }
}

TEMPLATE_TEST_CASE("string: static_string::append(string_view,pos,count)",
    "[string]", etl::static_string<12>, etl::static_string<32>)
{
    SECTION("empty")
    {
        etl::string_view emptySrc {};

        TestType empty {};
        empty.append(emptySrc, 0);
        CHECK(empty.empty());
    }

    SECTION("no nulls")
    {
        etl::string_view src { "_test" };

        TestType dest { "abc" };
        dest.append(src, 2, 1);
        CHECK(dest == "abce"_sv);
    }
}

TEMPLATE_TEST_CASE("string: static_string::operator+=", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    SECTION("string")
    {
        TestType src { "_test" };
        TestType dest { "abc" };
        dest += src;
        CHECK(dest == "abc_test"_sv);
    }

    SECTION("char")
    {
        auto src = 'a';
        TestType dest { "abc" };
        dest += src;
        CHECK(dest == "abca"_sv);
    }

    SECTION("char const*")
    {
        auto const* src = "_test";
        TestType dest { "abc" };
        dest += src;
        CHECK(dest == "abc_test"_sv);
    }

    SECTION("string_view")
    {
        etl::string_view src { "_test" };
        TestType dest { "abc" };
        dest += src;
        CHECK(dest == "abc_test"_sv);
    }
}

TEMPLATE_TEST_CASE("string: algorithms", "[string]", etl::static_string<12>,
    etl::static_string<32>)
{
    // setup
    TestType str { "aaaaaa" };
    etl::for_each(str.begin(), str.end(), [](auto& c) { c++; });

    // test
    etl::for_each(
        str.cbegin(), str.cend(), [](auto const& c) { REQUIRE(c == 'b'); });

    REQUIRE(str.front() == 'b');
    REQUIRE(str.back() == 'b');
}

TEMPLATE_TEST_CASE("string: static_string::front/back", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    TestType str { "junk" };
    CHECK(str.front() == 'j');
    CHECK(etl::as_const(str).front() == 'j');

    CHECK(str.back() == 'k');
    CHECK(etl::as_const(str).back() == 'k');
}

TEMPLATE_TEST_CASE("string: static_string::data/c_str", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    TestType str { "junk" };
    CHECK(str.data() == str.c_str());
    CHECK(str.c_str() != nullptr);
    CHECK(str.c_str()[0] == 'j');
}

TEMPLATE_TEST_CASE("string: static_string::operator string_view", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    TestType str { "junk" };
    auto sv = etl::string_view { str };
    CHECK(sv.data()[0] == 'j');
}

TEMPLATE_TEST_CASE("string: static_string::clear", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    // setup
    TestType str { "junk" };
    REQUIRE(str.empty() == false);

    // test
    str.clear();
    REQUIRE(str.capacity() == str.max_size());
    REQUIRE(str.empty() == true);
    REQUIRE(str.size() == etl::size_t(0));
}

TEMPLATE_TEST_CASE("string: static_string::push_back", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    TestType str { "" };
    str.push_back('a');
    str.push_back('b');
    REQUIRE(str == TestType("ab"));
    REQUIRE(str.size() == 2);
}

TEMPLATE_TEST_CASE("string: static_string::pop_back", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    TestType str { "abc" };
    str.pop_back();
    str.pop_back();
    REQUIRE(str == TestType("a"));
    REQUIRE(str == "a");
    REQUIRE(str.size() == 1);
}

TEMPLATE_TEST_CASE("string: static_string::insert(index, count, CharType)",
    "[string]", etl::static_string<12>, etl::static_string<32>)
{
    SECTION("on empty string")
    {
        auto str = TestType();
        str.insert(0, 4, 'a');
        CHECK(str.size() == 4);
        CHECK(etl::strlen(str.data()) == str.size());
        CHECK(str == "aaaa"_sv);
    }

    SECTION("on filled string")
    {
        auto str = TestType("test");
        str.insert(0, 4, 'a');
        CHECK(str.size() == 8);
        CHECK(etl::strlen(str.data()) == str.size());
        CHECK(str == "aaaatest"_sv);

        str = TestType("test");
        str.insert(1, 2, 'a');
        str.insert(0, 1, 'b');
        CHECK(str.size() == 7);
        CHECK(etl::strlen(str.data()) == str.size());
        CHECK(str == "btaaest"_sv);

        str = TestType("test");
        str.insert(str.size(), 2, 'a');
        CHECK(str.size() == 6);
        CHECK(etl::strlen(str.data()) == str.size());
        CHECK(str == "testaa"_sv);
    }

    SECTION("on full string")
    {
        auto str = TestType("");
        str.insert(0, str.capacity(), 'a');
        CHECK(str.full());
        CHECK(str.size() == str.capacity() - 1);
        CHECK(etl::strlen(str.data()) == str.size());
        CHECK(etl::all_of(
            begin(str), end(str), [](auto ch) { return ch == 'a'; }));
    }
}

TEMPLATE_TEST_CASE("string: static_string::insert(index, CharType const*)",
    "[string]", etl::static_string<12>, etl::static_string<32>)
{
    SECTION("on empty string")
    {
        auto str = TestType();
        str.insert(0, "aaaa");
        CHECK(str.size() == 4);
        CHECK(etl::strlen(str.data()) == str.size());
        CHECK(str == "aaaa"_sv);
    }

    SECTION("on filled string")
    {
        auto str = TestType("test");
        str.insert(0, "abcd");
        CHECK(str.size() == 8);
        CHECK(etl::strlen(str.data()) == str.size());
        CHECK(str == "abcdtest"_sv);

        str = TestType("test");
        str.insert(1, "aa");
        str.insert(0, "b");
        CHECK(str.size() == 7);
        CHECK(etl::strlen(str.data()) == str.size());
        CHECK(str == "btaaest"_sv);

        str = TestType("test");
        str.insert(str.size(), "aa");
        CHECK(str.size() == 6);
        CHECK(etl::strlen(str.data()) == str.size());
        CHECK(str == "testaa"_sv);
    }

    SECTION("on full string")
    {
        auto str = TestType("");
        for (etl::size_t i = 0; i < str.capacity(); ++i) { str.insert(0, "a"); }

        CHECK(str.full());
        CHECK(str.size() == str.capacity() - 1);
        CHECK(etl::strlen(str.data()) == str.size());
        CHECK(etl::all_of(
            begin(str), end(str), [](auto ch) { return ch == 'a'; }));
    }
}

TEMPLATE_TEST_CASE(
    "string: static_string::insert(index, CharType const*, count)", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    SECTION("on empty string")
    {
        auto str = TestType();
        str.insert(0, "aaaa", 4);
        CHECK(str.size() == 4);
        CHECK(etl::strlen(str.data()) == str.size());
        CHECK(str == "aaaa"_sv);
    }

    SECTION("on filled string")
    {
        auto str = TestType("test");
        str.insert(0, "abcd", 3);
        CHECK(str.size() == 7);
        CHECK(etl::strlen(str.data()) == str.size());
        CHECK(str == "abctest"_sv);

        str = TestType("test");
        str.insert(1, "aa", 2);
        str.insert(0, "b", 1);
        CHECK(str.size() == 7);
        CHECK(etl::strlen(str.data()) == str.size());
        CHECK(str == "btaaest"_sv);

        str = TestType("test");
        str.insert(str.size(), "aa", 1);
        CHECK(str.size() == 5);
        CHECK(etl::strlen(str.data()) == str.size());
        CHECK(str == "testa"_sv);
    }

    SECTION("on full string")
    {
        auto str = TestType("");
        for (etl::size_t i = 0; i < str.capacity(); ++i) {
            str.insert(0, "ab", 1);
        }

        CHECK(str.full());
        CHECK(str.size() == str.capacity() - 1);
        CHECK(etl::strlen(str.data()) == str.size());
        CHECK(etl::all_of(
            begin(str), end(str), [](auto ch) { return ch == 'a'; }));
    }
}

TEMPLATE_TEST_CASE("string: static_string::erase", "[string]",
    etl::static_string<32>, etl::static_string<64>)
{
    SECTION("cpprefrence example")
    {
        TestType str = "This is an example";

        // Erase "This "
        str.erase(0, 5);
        CHECK(str == "is an example"_sv);

        // Erase ' '
        CHECK(*str.erase(etl::find(begin(str), end(str), ' ')) == 'a');
        CHECK(str == "isan example"_sv);

        // Trim from ' ' to the end of the string
        str.erase(str.find(' '));
        CHECK(str == "isan"_sv);
    }
}

TEMPLATE_TEST_CASE("string: static_string::resize", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    SECTION("default char")
    {
        auto str = TestType();
        CHECK(str.empty() == true);

        // grow
        str.resize(2);
        CHECK(str.empty() == false);
        CHECK(str.size() == 2);
        CHECK(str[0] == '\0');
        CHECK(str[1] == '\0');

        // shrink
        str.resize(1);
        CHECK(str.empty() == false);
        CHECK(str.size() == 1);
        CHECK(str[0] == '\0');
    }

    SECTION("provided char")
    {
        auto str = TestType();
        CHECK(str.empty() == true);

        // grow
        str.resize(2, 'a');
        CHECK(str.empty() == false);
        CHECK(str.size() == 2);
        CHECK(str[0] == 'a');
        CHECK(str[1] == 'a');

        // shrink
        str.resize(1, 'a');
        CHECK(str.empty() == false);
        CHECK(str.size() == 1);
        CHECK(str[0] == 'a');
    }
}

TEMPLATE_TEST_CASE("string: static_string::starts_with", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    using namespace etl::literals;

    SECTION("empty string")
    {
        auto str = TestType();
        CHECK_FALSE(str.starts_with("foo"_sv));
        CHECK_FALSE(str.starts_with("foo"));
        CHECK_FALSE(str.starts_with('f'));
    }

    SECTION("false")
    {
        auto str = TestType("test");
        CHECK_FALSE(str.starts_with("foo"_sv));
        CHECK_FALSE(str.starts_with("foo"));
        CHECK_FALSE(str.starts_with('f'));
    }

    SECTION("true")
    {
        auto str1 = TestType("foo");
        CHECK(str1.starts_with("foo"_sv));
        CHECK(str1.starts_with("foo"));
        CHECK(str1.starts_with('f'));

        auto str2 = TestType { "foobar" };
        CHECK(str2.starts_with("foo"_sv));
        CHECK(str2.starts_with("foo"));
        CHECK(str2.starts_with('f'));
    }
}

TEMPLATE_TEST_CASE("string: static_string::ends_with", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    using namespace etl::literals;

    SECTION("empty string")
    {
        auto str = TestType();
        CHECK_FALSE(str.ends_with("foo"_sv));
        CHECK_FALSE(str.ends_with("foo"));
        CHECK_FALSE(str.ends_with('o'));
    }

    SECTION("false")
    {
        auto str = TestType("test");
        CHECK_FALSE(str.ends_with("foo"_sv));
        CHECK_FALSE(str.ends_with("foo"));
        CHECK_FALSE(str.ends_with('o'));
    }

    SECTION("true")
    {
        auto str = TestType("foo");
        CHECK(str.ends_with("foo"_sv));
        CHECK(str.ends_with("foo"));
        CHECK(str.ends_with('o'));

        auto str2 = TestType("barfoo");
        CHECK(str2.ends_with("foo"_sv));
        CHECK(str2.ends_with("foo"));
        CHECK(str2.ends_with('o'));
    }
}

TEMPLATE_TEST_CASE("string: static_string::replace", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    using namespace etl::literals;
    using string_t = TestType;

    auto s = string_t("0123456");
    CHECK(s.replace(0, 2, string_t("xx")) == "xx23456"_sv);
    CHECK(s.replace(2, 1, string_t("xx")) == "xxx3456"_sv);
    CHECK(s.replace(begin(s) + 3, begin(s) + 4, string_t("x")) == "xxxx456"_sv);
}

TEMPLATE_TEST_CASE("string: static_string::substr", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    using namespace etl::literals;

    SECTION("empty ")
    {
        auto str = TestType();
        CHECK(str.substr().size() == 0);
        CHECK(str.substr(1).size() == 0);
        CHECK(str.substr(10).size() == 0);
    }

    SECTION("non empty")
    {
        auto str = TestType("abcd");
        CHECK(str.size() == 4);
        CHECK(str.substr(0, 1).size() == 1);
        CHECK(str.substr(1).size() == 3);
        CHECK(str.substr(10).size() == 0);
    }
}

TEMPLATE_TEST_CASE("string: static_string::copy", "[string]",
    (etl::static_string<12>), (etl::static_string<32>))
{
    SECTION("empty")
    {
        char destination[32] = {};
        auto str             = TestType();
        CHECK(str.empty());
        CHECK(str.copy(destination, 0, 0) == 0);
        CHECK(str.copy(destination, 1, 0) == 0);
        CHECK(str.copy(destination, 10, 1) == 0);
    }

    SECTION("non empty")
    {
        char destination[32] = {};
        auto const* src      = "abcd";
        auto str             = TestType { src };
        CHECK(str.size() == 4);

        CHECK(str.copy(destination, 1, 0) == 1);
        CHECK(destination[0] == 'a');
        CHECK(destination[1] == '\0');

        CHECK(str.copy(destination, 2, 2) == 2);
        CHECK(destination[0] == 'c');
        CHECK(destination[1] == 'd');
        CHECK(destination[2] == '\0');

        CHECK(str.copy(destination, str.size()) == 4);
        CHECK(destination[0] == 'a');
        CHECK(destination[1] == 'b');
        CHECK(destination[2] == 'c');
        CHECK(destination[3] == 'd');
        CHECK(destination[4] == '\0');
    }
}

TEMPLATE_TEST_CASE("string: static_string::swap", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    SECTION("empty")
    {
        auto lhs = TestType();
        auto rhs = TestType();
        CHECK(lhs.empty());
        CHECK(rhs.empty());

        lhs.swap(rhs);
        CHECK(lhs.empty());
        CHECK(rhs.empty());
    }

    SECTION("same size")
    {
        auto lhs = TestType { "abc" };
        auto rhs = TestType { "def" };
        CHECK(lhs.size() == rhs.size());

        etl::swap(lhs, rhs);
        CHECK(lhs.size() == rhs.size());

        CHECK(lhs == "def");
        CHECK(rhs == "abc");
    }

    SECTION("different size")
    {
        auto lhs = TestType("foo");
        auto rhs = TestType { "barbaz" };
        CHECK(lhs.size() != rhs.size());

        lhs.swap(rhs);
        CHECK(lhs.size() != rhs.size());

        CHECK(lhs == "barbaz");
        CHECK(rhs == "foo");
    }
}

TEMPLATE_TEST_CASE("string: static_string::compare(string)", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    SECTION("empty string same capacity")
    {
        auto lhs = TestType();
        auto rhs = TestType();

        CHECK(lhs.compare(rhs) == 0);
        CHECK(rhs.compare(lhs) == 0);
    }

    SECTION("empty string different capacity")
    {
        auto lhs = TestType();
        auto rhs = etl::static_string<2> {};

        CHECK(lhs.compare(rhs) == 0);
        CHECK(rhs.compare(lhs) == 0);
    }

    SECTION("same size equal")
    {
        auto const lhs = TestType("test");
        auto const rhs = TestType("test");

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

        CHECK(TestType("te").compare(0, 2, "test"_sv, 0, 2) == 0);
        CHECK(TestType("abcabc").compare(3, 3, "abc"_sv, 0, 3) == 0);
        CHECK(TestType("abcabc").compare(3, 1, "abc"_sv, 0, 3) < 0);
        CHECK(TestType("abcabc").compare(3, 3, "abc"_sv, 0, 1) > 0);

        CHECK(TestType("abcabc").compare(3, 3, "abc", 3) == 0);
        CHECK(TestType("abcabc").compare(3, 1, "abc", 0, 3) < 0);
        CHECK(TestType("abcabc").compare(3, 3, "abc", 0, 1) > 0);
    }

    SECTION("different size equal")
    {
        auto const lhs = TestType("test");
        auto const rhs = TestType("te");

        CHECK(lhs.compare(rhs) > 0);
        CHECK(rhs.compare("test"_sv) < 0);

        auto other = etl::static_string<9> { "te" };
        CHECK(lhs.compare(other) > 0);
        CHECK(other.compare(etl::string_view("te")) == 0);
    }
}

TEMPLATE_TEST_CASE("string: static_string::find(string)", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    SECTION("empty string")
    {
        auto str = TestType();
        CHECK(str.find(TestType(), 0) == 0);
        CHECK(str.find(TestType(), 1) == TestType::npos);
        CHECK(str.find(TestType { "" }) == 0);
    }

    SECTION("not found")
    {
        auto str = TestType { "def" };
        CHECK(str.find(TestType { "abc" }, 0) == TestType::npos);
        CHECK(str.find(TestType { "abc" }, 1) == TestType::npos);
        CHECK(str.find(TestType { "abc" }) == TestType::npos);
    }

    SECTION("found")
    {
        auto str = TestType("abcd");
        CHECK(str.find(TestType { "abc" }, 0) == 0);
        CHECK(str.find(TestType { "bc" }, 1) == 1);
        CHECK(str.find(TestType { "cd" }) == 2);
    }
}

TEMPLATE_TEST_CASE("string: static_string::find(char const*)", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    SECTION("empty string")
    {
        auto str = TestType();
        CHECK(str.find("") == 0);
        CHECK(str.find("", 0) == 0);
        CHECK(str.find("", 1) == TestType::npos);
    }

    SECTION("not found")
    {
        auto str = TestType { "def" };
        CHECK(str.find("abc", 0) == TestType::npos);
        CHECK(str.find("abc", 1) == TestType::npos);
        CHECK(str.find("abc") == TestType::npos);
    }

    SECTION("found")
    {
        auto str = TestType("abcd");
        CHECK(str.find("abc", 0) == 0);
        CHECK(str.find("bc", 1) == 1);
        CHECK(str.find("cd") == 2);
    }
}

TEMPLATE_TEST_CASE("string: static_string::find(char)", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    SECTION("empty string")
    {
        auto str = TestType();
        CHECK(str.find('a', 0) == TestType::npos);
        CHECK(str.find('a', 1) == TestType::npos);
        CHECK(str.find('a') == TestType::npos);
    }

    SECTION("not found")
    {
        auto str = TestType { "bcdef" };
        CHECK(str.find('a', 0) == TestType::npos);
        CHECK(str.find('a', 1) == TestType::npos);
        CHECK(str.find('a') == TestType::npos);
    }

    SECTION("found")
    {
        auto str = TestType("abcd");
        CHECK(str.find('a', 0) == 0);
        CHECK(str.find('b', 1) == 1);
        CHECK(str.find('c') == 2);
    }
}

TEMPLATE_TEST_CASE("string: static_string::rfind(string)", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    SECTION("empty string")
    {
        auto str = TestType("test");
        CHECK(str.rfind(TestType()) == 0);
        CHECK(str.rfind(TestType(), 0) == 0);
        CHECK(str.rfind(TestType(), TestType::npos) == str.size());
    }

    SECTION("not found")
    {
        auto str = TestType { "def" };
        CHECK(str.rfind(TestType { "abc" }, 0) == TestType::npos);
        CHECK(str.rfind(TestType { "abc" }, 1) == TestType::npos);
        CHECK(str.rfind(TestType { "abc" }) == TestType::npos);
    }

    SECTION("found")
    {
        // auto const str = TestType ("test");
        // CHECK(str.rfind(TestType {"t"}) == 3);
        // CHECK(str.rfind(TestType {"est"}) == 1);

        // CHECK(str.rfind(TestType {"st"}, 12) == 2);
        // CHECK(str.rfind(TestType {"st"}, 12) == 2);
    }
}

TEMPLATE_TEST_CASE("string: static_string::rfind(char const*)", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    SECTION("empty string")
    {
        auto str = TestType("test");
        CHECK(str.rfind("") == 0);
        CHECK(str.rfind("", 0) == 0);
        CHECK(str.rfind("", TestType::npos) == str.size());
    }

    SECTION("not found")
    {
        auto str = TestType { "def" };
        CHECK(str.rfind("abc", 0) == TestType::npos);
        CHECK(str.rfind("abc", 1) == TestType::npos);
        CHECK(str.rfind("abc") == TestType::npos);
    }

    SECTION("found")
    {
        auto const str = TestType("test");
        CHECK(str.rfind("t") == 0);
        // CHECK(str.rfind("t", 1) == 3);
        // CHECK(str.rfind("est") == 1);

        // CHECK(str.rfind("st", 12) == 2);
        // CHECK(str.rfind("st", 12) == 2);
    }
}

TEMPLATE_TEST_CASE("string: static_string::find_first_of(string)", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    SECTION("empty string")
    {
        auto str = TestType();
        CHECK(str.find_first_of(TestType(), 0) == TestType::npos);
        CHECK(str.find_first_of(TestType(), 1) == TestType::npos);
        CHECK(str.find_first_of(TestType { "" }) == TestType::npos);
    }

    SECTION("not found")
    {
        auto str = TestType { "def" };
        CHECK(str.find_first_of(TestType { "abc" }, 0) == TestType::npos);
        CHECK(str.find_first_of(TestType { "abc" }, 1) == TestType::npos);
        CHECK(str.find_first_of(TestType { "abc" }) == TestType::npos);
    }

    SECTION("found")
    {
        auto str = TestType("abcd");
        CHECK(str.find_first_of(TestType { "abc" }, 0) == 0);
        CHECK(str.find_first_of(TestType { "bc" }, 1) == 1);
        CHECK(str.find_first_of(TestType { "cd" }) == 2);
    }
}

TEMPLATE_TEST_CASE("string: static_string::find_first_of(char const*)",
    "[string]", etl::static_string<12>, etl::static_string<32>)
{
    SECTION("empty string")
    {
        auto str = TestType();
        CHECK(str.find_first_of("", 0) == TestType::npos);
        CHECK(str.find_first_of("", 1) == TestType::npos);
        CHECK(str.find_first_of("") == TestType::npos);
    }

    SECTION("not found")
    {
        auto str = TestType { "def" };
        CHECK(str.find_first_of("abc", 0) == TestType::npos);
        CHECK(str.find_first_of("abc", 1) == TestType::npos);
        CHECK(str.find_first_of("abc") == TestType::npos);
    }

    SECTION("found")
    {
        auto str = TestType("abcd");
        CHECK(str.find_first_of("abc", 0) == 0);
        CHECK(str.find_first_of("bc", 1) == 1);
        CHECK(str.find_first_of("cd") == 2);
    }
}
TEMPLATE_TEST_CASE("string: static_string::find_first_of(string_view)",
    "[string]", etl::static_string<12>, etl::static_string<32>)
{
    using namespace etl::string_view_literals;

    SECTION("empty string")
    {
        auto str = TestType();
        CHECK(str.find_first_of(""_sv, 0) == TestType::npos);
        CHECK(str.find_first_of(""_sv, 1) == TestType::npos);
        CHECK(str.find_first_of(""_sv) == TestType::npos);
    }

    SECTION("not found")
    {
        auto str = TestType { "def" };
        CHECK(str.find_first_of("abc"_sv, 0) == TestType::npos);
        CHECK(str.find_first_of("abc"_sv, 1) == TestType::npos);
        CHECK(str.find_first_of("abc"_sv) == TestType::npos);
    }

    SECTION("found")
    {
        auto str = TestType("abcd");
        CHECK(str.find_first_of("abc"_sv, 0) == 0);
        CHECK(str.find_first_of("bc"_sv, 1) == 1);
        CHECK(str.find_first_of("cd"_sv) == 2);
    }
}

TEMPLATE_TEST_CASE("string: static_string::find_first_of(char)", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    SECTION("empty string")
    {
        auto str = TestType();
        CHECK(str.find_first_of('a', 0) == TestType::npos);
        CHECK(str.find_first_of('a', 1) == TestType::npos);
        CHECK(str.find_first_of('a') == TestType::npos);
    }

    SECTION("not found")
    {
        auto str = TestType { "def" };
        CHECK(str.find_first_of('a', 0) == TestType::npos);
        CHECK(str.find_first_of('a', 1) == TestType::npos);
        CHECK(str.find_first_of('a') == TestType::npos);
    }

    SECTION("found")
    {
        auto str = TestType("abcd");
        CHECK(str.find_first_of('a', 0) == 0);
        CHECK(str.find_first_of('b', 1) == 1);
        CHECK(str.find_first_of('c') == 2);
    }
}

TEMPLATE_TEST_CASE("string: static_string::find_first_not_of", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    auto str = TestType { "BCDEF" };

    REQUIRE(str.find_first_not_of("ABC") == 2);
    REQUIRE(str.find_first_not_of("ABC", 4) == 4);
    REQUIRE(str.find_first_not_of('B') == 1);
    REQUIRE(str.find_first_not_of('D', 2) == 3);
}

TEMPLATE_TEST_CASE("string: static_string::operator==/!=", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    SECTION("empty string same capacity")
    {
        auto lhs = TestType();
        auto rhs = TestType();

        CHECK(lhs == "");
        CHECK(lhs == rhs);
        CHECK_FALSE(lhs != rhs);
        CHECK(rhs == lhs);
        CHECK_FALSE(rhs != lhs);
    }

    SECTION("empty string different capacity")
    {
        auto lhs = TestType();
        auto rhs = etl::static_string<2> {};

        CHECK(lhs == "");
        CHECK(rhs == "");
        CHECK(lhs == rhs);
        CHECK_FALSE(lhs != rhs);
        CHECK_FALSE(lhs != "");
        CHECK(rhs == lhs);
        CHECK_FALSE(rhs != lhs);
    }
}

TEMPLATE_TEST_CASE("string: static_string::operator<", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    using string = TestType;

    SECTION("empty string")
    {
        CHECK_FALSE(string {} < "");
        CHECK_FALSE(string {} < string {});
        CHECK_FALSE(string {} < etl::static_string<2> {});
        CHECK_FALSE(etl::static_string<4> {} < string {});
    }

    SECTION("string same capacity")
    {
        CHECK(string { "abc" } < "def");
        CHECK(string { "abc" } < string { "def" });
        CHECK(string { "abc" } < string { "defg" });
    }

    SECTION("string different capacity")
    {
        CHECK_FALSE(string { "def" } < "a");
        CHECK_FALSE(string { "def" } < etl::static_string<2> { "a" });
        CHECK(etl::static_string<2> { "a" } < string("test"));
    }
}

TEMPLATE_TEST_CASE("string: static_string::operator<=", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    using string = TestType;

    SECTION("empty string")
    {
        CHECK(string {} <= "");
        CHECK(string {} <= string {});
        CHECK(string {} <= etl::static_string<2> {});
        CHECK(etl::static_string<4> {} <= string {});
    }

    SECTION("string same capacity")
    {
        CHECK(string { "abc" } <= "def");
        CHECK(string { "abc" } <= string { "def" });
        CHECK(string { "abc" } <= string { "defg" });
        CHECK(string { "abc" } <= string { "abc" });
    }

    SECTION("string different capacity")
    {
        CHECK_FALSE(string { "def" } <= "a");
        CHECK_FALSE(string { "def" } <= etl::static_string<2> { "a" });
        CHECK(etl::static_string<2> { "a" } <= string("test"));
    }
}

TEMPLATE_TEST_CASE("string: static_string::operator>", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    using string = TestType;

    SECTION("empty string")
    {
        CHECK_FALSE(string {} > "");
        CHECK_FALSE(string {} > string {});
        CHECK_FALSE(string {} > etl::static_string<2> {});
        CHECK_FALSE(etl::static_string<4> {} > string {});
    }

    SECTION("string same capacity")
    {
        CHECK_FALSE(string { "abc" } > "def");
        CHECK_FALSE(string { "abc" } > string { "def" });
        CHECK_FALSE(string { "abc" } > string { "defg" });
        CHECK_FALSE(string { "abc" } > string { "abc" });
    }

    SECTION("string different capacity")
    {
        CHECK(string { "def" } > etl::static_string<2> { "a" });
        CHECK_FALSE(etl::static_string<2> { "a" } > string("test"));
    }
}

TEMPLATE_TEST_CASE("string: static_string::operator>=", "[string]",
    etl::static_string<12>, etl::static_string<32>)
{
    using string = TestType;

    SECTION("empty string")
    {
        CHECK(string {} >= "");
        CHECK(string {} >= string {});
        CHECK(string {} >= etl::static_string<2> {});
        CHECK(etl::static_string<4> {} >= string {});
    }

    SECTION("string same capacity")
    {
        CHECK(string { "abc" } >= "abc");
        CHECK(string { "abc" } >= string { "abc" });
        CHECK_FALSE(string { "abc" } >= string { "def" });
        CHECK_FALSE(string { "abc" } >= string { "defg" });
    }

    SECTION("string different capacity")
    {
        CHECK(string { "def" } >= etl::static_string<2> { "a" });
        CHECK_FALSE(etl::static_string<2> { "a" } >= string("test"));
    }
}

TEMPLATE_TEST_CASE("string: stoi", "[string]", etl::static_string<12>,
    etl::static_string<24>, etl::static_string<32>, etl::static_string<48>,
    etl::static_string<64>)
{
    using string_t = TestType;

    auto [input, expected] = GENERATE(table<string_t, int>({
        { string_t { "0" }, 0 },
        { string_t { "1" }, 1 },
        { string_t { "2" }, 2 },
        { string_t { "3" }, 3 },
        { string_t { "4" }, 4 },
        { string_t { "5" }, 5 },
        { string_t { "6" }, 6 },
        { string_t { "7" }, 7 },
        { string_t { "8" }, 8 },
        { string_t { "9" }, 9 },
        { string_t { "10" }, 10 },
        { string_t { "11" }, 11 },
        { string_t { "99" }, 99 },
        { string_t { "11123" }, 11123 },

    }));

    CHECK(etl::stoi(input) == expected);
}

TEMPLATE_TEST_CASE("string: stol", "[string]", etl::static_string<12>,
    etl::static_string<24>, etl::static_string<32>, etl::static_string<48>,
    etl::static_string<64>)
{
    using string_t = TestType;

    auto [input, expected] = GENERATE(table<string_t, long>({
        { string_t { "0" }, 0L },
        { string_t { "1" }, 1L },
        { string_t { "2" }, 2L },
        { string_t { "3" }, 3L },
        { string_t { "4" }, 4L },
        { string_t { "5" }, 5L },
        { string_t { "6" }, 6L },
        { string_t { "7" }, 7L },
        { string_t { "8" }, 8L },
        { string_t { "9" }, 9L },
        { string_t { "10" }, 10L },
        { string_t { "11" }, 11L },
        { string_t { "99" }, 99L },
        { string_t { "11123" }, 11123L },

    }));

    CHECK(etl::stol(input) == expected);
}

TEMPLATE_TEST_CASE("string: stoll", "[string]", etl::static_string<12>,
    etl::static_string<24>, etl::static_string<32>, etl::static_string<48>,
    etl::static_string<64>)
{
    using string_t = TestType;

    auto [input, expected] = GENERATE(table<string_t, long long>({
        { string_t { "0" }, 0LL },
        { string_t { "1" }, 1LL },
        { string_t { "2" }, 2LL },
        { string_t { "3" }, 3LL },
        { string_t { "4" }, 4LL },
        { string_t { "5" }, 5LL },
        { string_t { "6" }, 6LL },
        { string_t { "7" }, 7LL },
        { string_t { "8" }, 8LL },
        { string_t { "9" }, 9LL },
        { string_t { "10" }, 10LL },
        { string_t { "11" }, 11LL },
        { string_t { "99" }, 99LL },
        { string_t { "11123" }, 11123LL },

    }));

    CHECK(etl::stoll(input) == expected);
}

TEMPLATE_TEST_CASE("string: stoul", "[string]", etl::static_string<12>,
    etl::static_string<24>, etl::static_string<32>, etl::static_string<48>,
    etl::static_string<64>)
{
    using string_t = TestType;

    auto [input, expected] = GENERATE(table<string_t, unsigned long>({
        { string_t { "0" }, 0UL },
        { string_t { "1" }, 1UL },
        { string_t { "2" }, 2UL },
        { string_t { "3" }, 3UL },
        { string_t { "4" }, 4UL },
        { string_t { "5" }, 5UL },
        { string_t { "6" }, 6UL },
        { string_t { "7" }, 7UL },
        { string_t { "8" }, 8UL },
        { string_t { "9" }, 9UL },
        { string_t { "10" }, 10UL },
        { string_t { "11" }, 11UL },
        { string_t { "99" }, 99UL },
        { string_t { "11123" }, 11123UL },

    }));

    CHECK(etl::stoul(input) == expected);
}

TEMPLATE_TEST_CASE("string: stoull", "[string]", etl::static_string<12>,
    etl::static_string<24>, etl::static_string<32>, etl::static_string<48>,
    etl::static_string<64>)
{
    using string_t = TestType;

    auto [input, expected] = GENERATE(table<string_t, unsigned long long>({
        { string_t { "0" }, 0ULL },
        { string_t { "1" }, 1ULL },
        { string_t { "2" }, 2ULL },
        { string_t { "3" }, 3ULL },
        { string_t { "4" }, 4ULL },
        { string_t { "5" }, 5ULL },
        { string_t { "6" }, 6ULL },
        { string_t { "7" }, 7ULL },
        { string_t { "8" }, 8ULL },
        { string_t { "9" }, 9ULL },
        { string_t { "10" }, 10ULL },
        { string_t { "11" }, 11ULL },
        { string_t { "99" }, 99ULL },
        { string_t { "11123" }, 11123ULL },

    }));

    CHECK(etl::stoull(input) == expected);
}

TEMPLATE_TEST_CASE("string: to_string", "[string]", int, long, long long,
    unsigned int, unsigned long, unsigned long long)
{
    auto [input, expected] = GENERATE(table<TestType, etl::string_view>({
        { TestType { 0 }, "0"_sv },
        { TestType { 1 }, "1"_sv },
        { TestType { 2 }, "2"_sv },
        { TestType { 3 }, "3"_sv },
        { TestType { 4 }, "4"_sv },
        { TestType { 5 }, "5"_sv },
        { TestType { 6 }, "6"_sv },
        { TestType { 7 }, "7"_sv },
        { TestType { 8 }, "8"_sv },
        { TestType { 9 }, "9"_sv },
        { TestType { 10 }, "10"_sv },
        { TestType { 11 }, "11"_sv },
        { TestType { 99 }, "99"_sv },
        { TestType { 100 }, "100"_sv },
        { TestType { 999 }, "999"_sv },
        { TestType { 9999 }, "9999"_sv },
        { TestType { 12345 }, "12345"_sv },

    }));

    CHECK(etl::to_string<8>(input) == expected);
    CHECK(etl::to_string<16>(input) == expected);
    CHECK(etl::to_string<32>(input) == expected);
    CHECK(etl::to_string<64>(input) == expected);
}