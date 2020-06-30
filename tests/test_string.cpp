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

#include "taetl/algorithm.hpp"
#include "taetl/string.hpp"

TEST_CASE("string: strlen", "[string]")
{
    STATIC_REQUIRE(taetl::strlen("") == 0);
    STATIC_REQUIRE(taetl::strlen("a") == 1);
    STATIC_REQUIRE(taetl::strlen("to") == 2);
    STATIC_REQUIRE(taetl::strlen("xxxxxxxxxx") == 10);
}

TEST_CASE("string: ctor - default", "[string]")
{
    taetl::string<16> str {};

    REQUIRE(str.empty() == true);
    REQUIRE(str.capacity() == str.max_size());
    REQUIRE(str.capacity() == taetl::size_t(16));
    REQUIRE(str.size() == taetl::size_t(0));
    REQUIRE(str.length() == taetl::size_t(0));
}

TEST_CASE("string: ctor - char const*", "[string]")
{
    taetl::string<16> str {"abc"};

    REQUIRE(str.empty() == false);
    REQUIRE(str.capacity() == str.max_size());
    REQUIRE(str.capacity() == taetl::size_t(16));
    REQUIRE(str.size() == taetl::size_t(3));
    REQUIRE(str.length() == taetl::size_t(3));
    REQUIRE(str[0] == 'a');
    REQUIRE(str[1] == 'b');
    REQUIRE(str[2] == 'c');
    REQUIRE(str[3] == char(0));
}

TEST_CASE("string: ctor - char const*, size_t", "[string]")
{
    taetl::string<16> str {"abc", 3};

    // INIT
    REQUIRE(str.empty() == false);
    REQUIRE(str.capacity() == str.max_size());
    REQUIRE(str.capacity() == taetl::size_t(16));
    REQUIRE(str.size() == taetl::size_t(3));
    REQUIRE(str.length() == taetl::size_t(3));
    REQUIRE(str[0] == 'a');
    REQUIRE(str[1] == 'b');
    REQUIRE(str[2] == 'c');
    REQUIRE(str[3] == char(0));
}

TEST_CASE("string: at", "[string]")
{
    taetl::string<16> str {"abc"};

    WHEN("mutable")
    {
        REQUIRE(str.at(0) == 'a');
        REQUIRE(str.at(1) == 'b');
        REQUIRE(str.at(2) == 'c');
        REQUIRE(str.at(3) == 0);
    }

    WHEN("const")
    {
        auto const& a = str.at(0);
        REQUIRE(a == 'a');
        auto const& b = str.at(1);
        REQUIRE(b == 'b');
        auto const& c = str.at(2);
        REQUIRE(c == 'c');
        auto const& null = str.at(3);
        REQUIRE(null == 0);
    }
}

TEST_CASE("string: begin/end", "[string]")
{
    taetl::string<16> str {};

    taetl::for_each(str.begin(), str.end(),
                    [](auto& c) { REQUIRE(c == char(0)); });
}

TEST_CASE("string: cbegin/cend", "[string]")
{
    taetl::string<16> str {};

    taetl::for_each(str.cbegin(), str.cend(),
                    [](auto const& c) { REQUIRE(c == char(0)); });
}

TEST_CASE("string: append", "[string]")
{
    taetl::string<16> str {};

    // APPEND 4 CHARACTERS
    const char* cptr = "C-string";
    str.append(cptr, 4);

    REQUIRE(str.empty() == false);
    REQUIRE(str.capacity() == str.max_size());
    REQUIRE(str.capacity() == taetl::size_t(16));
    REQUIRE(str.size() == taetl::size_t(4));
    REQUIRE(str.length() == taetl::size_t(4));
    REQUIRE(str[0] == 'C');
    REQUIRE(str[1] == '-');
    REQUIRE(str[2] == 's');
    REQUIRE(str[3] == 't');
    REQUIRE(str[4] == char(0));
}

TEST_CASE("string: algorithms", "[string]")
{
    // setup
    taetl::string<16> str {"aaaaaa"};
    taetl::for_each(str.begin(), str.end(), [](auto& c) { c++; });

    // test
    taetl::for_each(str.cbegin(), str.cend(),
                    [](auto const& c) { REQUIRE(c == 'b'); });

    REQUIRE(str.front() == 'b');
    REQUIRE(str.back() == 'b');
}

TEST_CASE("string: clear", "[string]")
{
    // setup
    taetl::string<16> str {"junk"};
    REQUIRE(str.empty() == false);

    // test
    str.clear();
    REQUIRE(str.capacity() == taetl::size_t(16));
    REQUIRE(str.capacity() == str.max_size());
    REQUIRE(str.empty() == true);
    REQUIRE(str.size() == taetl::size_t(0));
}

TEST_CASE("string: insert(index, count, CharType)", "[string]")
{
    auto str = taetl::small_string {};
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

TEST_CASE("string: insert(index, CharType const*)", "[string]")
{
    auto str = taetl::small_string {};
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

TEST_CASE("string: insert(index, CharType const*, count)", "[string]")
{
    auto str = taetl::small_string {};
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
