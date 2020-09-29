/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#include "catch2/catch.hpp"

#include "etl/algorithm.hpp"    // for for_each
#include "etl/definitions.hpp"  // for size_t
#include "etl/string.hpp"       // for static_string

TEST_CASE("string/char_traits: <char>::length", "[string]")
{
    STATIC_REQUIRE(etl::char_traits<char>::length("") == 0);
    STATIC_REQUIRE(etl::char_traits<char>::length("a") == 1);
    STATIC_REQUIRE(etl::char_traits<char>::length("to") == 2);
    STATIC_REQUIRE(etl::char_traits<char>::length("xxxxxxxxxx") == 10);
}

TEST_CASE("string/char_traits: <char>::eq", "[string]")
{
    STATIC_REQUIRE(etl::char_traits<char>::eq('a', 'a') == true);
    STATIC_REQUIRE(etl::char_traits<char>::eq('a', 'b') == false);
    STATIC_REQUIRE(etl::char_traits<char>::eq('b', 'a') == false);
}

TEST_CASE("string/char_traits: <char>::lt", "[string]")
{
    STATIC_REQUIRE(etl::char_traits<char>::lt('a', 'a') == false);
    STATIC_REQUIRE(etl::char_traits<char>::lt('a', 'b') == true);
    STATIC_REQUIRE(etl::char_traits<char>::lt('b', 'a') == false);
}

TEST_CASE("string/char_traits: <char>::assign(char,char)", "[string]")
{
    auto ch = [](char const& b) {
        auto a = 'a';
        etl::char_traits<char>::assign(a, b);
        return a;
    };

    STATIC_REQUIRE(ch('b') == 'b');
}

TEMPLATE_TEST_CASE("string: ctor - default", "[string]", etl::static_string<12>,
                   etl::static_string<32>, etl::static_string<12> const,
                   etl::static_string<32> const)
{
    TestType str {};

    REQUIRE(str.empty() == true);
    REQUIRE(str.capacity() == str.max_size());
    REQUIRE(str.size() == etl::size_t(0));
    REQUIRE(str.length() == etl::size_t(0));
}

TEMPLATE_TEST_CASE("string: ctor - char const*", "[string]", etl::static_string<12>,
                   etl::static_string<32>, etl::static_string<12> const,
                   etl::static_string<32> const)
{
    TestType str {"abc"};

    REQUIRE(str.empty() == false);
    REQUIRE(str.capacity() == str.max_size());
    REQUIRE(str.size() == etl::size_t(3));
    REQUIRE(str.length() == etl::size_t(3));
    REQUIRE(str[0] == 'a');
    REQUIRE(str[1] == 'b');
    REQUIRE(str[2] == 'c');
    REQUIRE(str[3] == char(0));
}

TEMPLATE_TEST_CASE("string: ctor - char const*, size_t", "[string]",
                   etl::static_string<12>, etl::static_string<32>,
                   etl::static_string<12> const, etl::static_string<32> const)
{
    TestType str {"abc", 3};

    REQUIRE(str.empty() == false);
    REQUIRE(str.capacity() == str.max_size());
    REQUIRE(str.size() == etl::size_t(3));
    REQUIRE(str.length() == etl::size_t(3));
    REQUIRE(str[0] == 'a');
    REQUIRE(str[1] == 'b');
    REQUIRE(str[2] == 'c');
    REQUIRE(str[3] == char(0));
}

TEMPLATE_TEST_CASE("string: constexpr", "[string]", etl::static_string<8>,
                   etl::static_string<12>, etl::static_string<32>)
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
    STATIC_REQUIRE(str2.size() == 4);
    STATIC_REQUIRE(str2.length() == 4);
    STATIC_REQUIRE(str2[0] == 'C');
    STATIC_REQUIRE(str2[1] == '-');
    STATIC_REQUIRE(str2[2] == 's');
    STATIC_REQUIRE(str2[3] == 't');
    STATIC_REQUIRE(str2[4] == 0);
    STATIC_REQUIRE(str2.at(4) == 0);
}

TEMPLATE_TEST_CASE("string: at", "[string]", etl::static_string<12>,
                   etl::static_string<32>, etl::static_string<12> const,
                   etl::static_string<32> const)
{
    TestType str {"abc"};
    REQUIRE(str.at(0) == 'a');
    REQUIRE(str.at(1) == 'b');
    REQUIRE(str.at(2) == 'c');
    REQUIRE(str.at(3) == 0);
}

TEMPLATE_TEST_CASE("string: operator[]", "[string]", etl::static_string<12>,
                   etl::static_string<32>, etl::static_string<12> const,
                   etl::static_string<32> const)
{
    TestType str {"abc"};
    REQUIRE(str[0] == 'a');
    REQUIRE(str[1] == 'b');
    REQUIRE(str[2] == 'c');
    REQUIRE(str[3] == 0);
}

TEMPLATE_TEST_CASE("string: begin/end", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
    TestType str {};

    etl::for_each(str.begin(), str.end(), [](auto& c) { REQUIRE(c == char(0)); });
}

TEMPLATE_TEST_CASE("string: cbegin/cend", "[string]", etl::static_string<12>,
                   etl::static_string<32>, etl::static_string<12> const,
                   etl::static_string<32> const)
{
    TestType str {};

    etl::for_each(str.cbegin(), str.cend(), [](auto const& c) { REQUIRE(c == char(0)); });
}

TEMPLATE_TEST_CASE("string: append(count, CharType)", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
    auto str = TestType {};
    str.append(4, 'a');

    REQUIRE(str.size() == etl::size_t(4));
    REQUIRE(str.length() == etl::size_t(4));
    REQUIRE(str[0] == 'a');
    REQUIRE(str[1] == 'a');
    REQUIRE(str[2] == 'a');
    REQUIRE(str[3] == 'a');
    REQUIRE(str[4] == char(0));
}

TEMPLATE_TEST_CASE("string: append(const_pointer, count)", "[string]",
                   etl::static_string<8>, etl::static_string<12>, etl::static_string<32>)
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
    REQUIRE(str[4] == char(0));
}

TEMPLATE_TEST_CASE("string: append(const_pointer)", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
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

TEMPLATE_TEST_CASE("string: algorithms", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
    // setup
    TestType str {"aaaaaa"};
    etl::for_each(str.begin(), str.end(), [](auto& c) { c++; });

    // test
    etl::for_each(str.cbegin(), str.cend(), [](auto const& c) { REQUIRE(c == 'b'); });

    REQUIRE(str.front() == 'b');
    REQUIRE(str.back() == 'b');
}

TEMPLATE_TEST_CASE("string: data/c_str", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
    TestType str {"junk"};
    CHECK(str.data() == str.c_str());
    CHECK(str.c_str() != nullptr);
    CHECK(str.c_str()[0] == 'j');
}

TEMPLATE_TEST_CASE("string: operator string_view", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
    TestType str {"junk"};
    auto sv = etl::string_view {str};
    CHECK(sv.data()[0] == 'j');
}

TEMPLATE_TEST_CASE("string: clear", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
    // setup
    TestType str {"junk"};
    REQUIRE(str.empty() == false);

    // test
    str.clear();
    REQUIRE(str.capacity() == str.max_size());
    REQUIRE(str.empty() == true);
    REQUIRE(str.size() == etl::size_t(0));
}

TEMPLATE_TEST_CASE("string: insert(index, count, CharType)", "[string]",
                   etl::static_string<12>, etl::static_string<32>)
{
    auto str = TestType {};
    REQUIRE(str.empty() == true);

    str.insert(0, 4, 'a');
    REQUIRE(str.empty() == false);
    REQUIRE(str.size() == 4);
    REQUIRE(str[0] == 'a');
    REQUIRE(str[1] == 'a');
    REQUIRE(str[2] == 'a');
    REQUIRE(str[3] == 'a');
    REQUIRE(str[4] == 0);
}

TEMPLATE_TEST_CASE("string: insert(index, CharType const*)", "[string]",
                   etl::static_string<12>, etl::static_string<32>)
{
    auto str = TestType {};
    REQUIRE(str.empty() == true);

    str.insert(0, "abcd");
    REQUIRE(str.empty() == false);
    REQUIRE(str.size() == 4);
    REQUIRE(str[0] == 'a');
    REQUIRE(str[1] == 'b');
    REQUIRE(str[2] == 'c');
    REQUIRE(str[3] == 'd');
    REQUIRE(str[4] == 0);
}

TEMPLATE_TEST_CASE("string: insert(index, CharType const*, count)", "[string]",
                   etl::static_string<12>, etl::static_string<32>)
{
    auto str = TestType {};
    REQUIRE(str.empty() == true);

    str.insert(0, "abcd", 3);
    REQUIRE(str.empty() == false);
    REQUIRE(str.size() == 3);
    REQUIRE(str[0] == 'a');
    REQUIRE(str[1] == 'b');
    REQUIRE(str[2] == 'c');
    REQUIRE(str[3] == 0);
    REQUIRE(str[4] == 0);
}

TEMPLATE_TEST_CASE("string: resize", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
    SECTION("default char")
    {
        auto str = TestType {};
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
        auto str = TestType {};
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

TEMPLATE_TEST_CASE("string: starts_with", "[string]", etl::static_string<12>,
                   etl::static_string<32>)
{
    using namespace etl::literals;

    SECTION("empty string")
    {
        auto str = TestType {};
        CHECK_FALSE(str.starts_with("foo"_sv));
        CHECK_FALSE(str.starts_with("foo"));
        CHECK_FALSE(str.starts_with('f'));
    }

    SECTION("false")
    {
        auto str = TestType {"test"};
        CHECK_FALSE(str.starts_with("foo"_sv));
        CHECK_FALSE(str.starts_with("foo"));
        CHECK_FALSE(str.starts_with('f'));
    }

    SECTION("true")
    {
        auto str = TestType {"foo"};
        CHECK(str.starts_with("foo"_sv));
        CHECK(str.starts_with("foo"));
        CHECK(str.starts_with('f'));
    }
}