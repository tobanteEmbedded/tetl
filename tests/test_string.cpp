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

#include "etl/algorithm.hpp"
#include "etl/string.hpp"

TEST_CASE("string: strlen", "[string]")
{
    STATIC_REQUIRE(etl::strlen("") == 0);
    STATIC_REQUIRE(etl::strlen("a") == 1);
    STATIC_REQUIRE(etl::strlen("to") == 2);
    STATIC_REQUIRE(etl::strlen("xxxxxxxxxx") == 10);
}

TEMPLATE_TEST_CASE("string: ctor - default", "[string]", etl::string<12>,
                   etl::small_string, etl::string<12> const,
                   etl::small_string const)
{
    TestType str {};

    REQUIRE(str.empty() == true);
    REQUIRE(str.capacity() == str.max_size());
    REQUIRE(str.size() == etl::size_t(0));
    REQUIRE(str.length() == etl::size_t(0));
}

TEMPLATE_TEST_CASE("string: ctor - char const*", "[string]", etl::string<12>,
                   etl::small_string, etl::string<12> const,
                   etl::small_string const)
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
                   etl::string<12>, etl::small_string, etl::string<12> const,
                   etl::small_string const)
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

TEMPLATE_TEST_CASE("string: at", "[string]", etl::string<12>, etl::small_string,
                   etl::string<12> const, etl::small_string const)
{
    TestType str {"abc"};
    REQUIRE(str.at(0) == 'a');
    REQUIRE(str.at(1) == 'b');
    REQUIRE(str.at(2) == 'c');
    REQUIRE(str.at(3) == 0);
}

TEMPLATE_TEST_CASE("string: operator[]", "[string]", etl::string<12>,
                   etl::small_string, etl::string<12> const,
                   etl::small_string const)
{
    TestType str {"abc"};
    REQUIRE(str[0] == 'a');
    REQUIRE(str[1] == 'b');
    REQUIRE(str[2] == 'c');
    REQUIRE(str[3] == 0);
}

TEMPLATE_TEST_CASE("string: begin/end", "[string]", etl::string<12>,
                   etl::small_string)
{
    TestType str {};

    etl::for_each(str.begin(), str.end(),
                  [](auto& c) { REQUIRE(c == char(0)); });
}

TEMPLATE_TEST_CASE("string: cbegin/cend", "[string]", etl::string<12>,
                   etl::small_string, etl::string<12> const,
                   etl::small_string const)
{
    TestType str {};

    etl::for_each(str.cbegin(), str.cend(),
                  [](auto const& c) { REQUIRE(c == char(0)); });
}

TEMPLATE_TEST_CASE("string: append(count, CharType)", "[string]",
                   etl::string<12>, etl::small_string)
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
                   etl::string<8>, etl::string<12>, etl::small_string)
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

TEMPLATE_TEST_CASE("string: append(const_pointer)", "[string]", etl::string<12>,
                   etl::small_string)
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

TEMPLATE_TEST_CASE("string: algorithms", "[string]", etl::string<12>,
                   etl::small_string)
{
    // setup
    TestType str {"aaaaaa"};
    etl::for_each(str.begin(), str.end(), [](auto& c) { c++; });

    // test
    etl::for_each(str.cbegin(), str.cend(),
                  [](auto const& c) { REQUIRE(c == 'b'); });

    REQUIRE(str.front() == 'b');
    REQUIRE(str.back() == 'b');
}

TEMPLATE_TEST_CASE("string: clear", "[string]", etl::string<12>,
                   etl::small_string)
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
                   etl::string<12>, etl::small_string)
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
                   etl::string<12>, etl::small_string)
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
                   etl::string<12>, etl::small_string)
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
