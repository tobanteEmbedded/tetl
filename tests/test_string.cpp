/*
Copyright (c) 2019, Tobias Hienzsch
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

TEST_CASE("string: defaults", "[string]")
{
    // Create array with capacity of 16 and size of 0
    taetl::String<char, 16> t_string {};

    // INIT
    REQUIRE(t_string.empty() == true);
    REQUIRE(t_string.capacity() == taetl::size_t(16));
    REQUIRE(t_string.size() == taetl::size_t(0));
    REQUIRE(t_string.length() == taetl::size_t(0));
}

TEST_CASE("string: begin/end", "[string]")
{
    taetl::String<char, 16> t_string {};

    taetl::for_each(t_string.begin(), t_string.end(),
                    [](auto& c) { REQUIRE(c == char(0)); });
}

TEST_CASE("string: cbegin/cend", "[string]")
{
    taetl::String<char, 16> t_string {};

    taetl::for_each(t_string.cbegin(), t_string.cend(),
                    [](auto const& c) { REQUIRE(c == char(0)); });
}

TEST_CASE("string: append", "[string]")
{
    taetl::String<char, 16> t_string {};

    // APPEND 4 CHARACTERS
    const char* cptr = "C-string";
    t_string.append(cptr, 4);

    REQUIRE(t_string.empty() == false);
    REQUIRE(t_string.capacity() == taetl::size_t(16));
    REQUIRE(t_string.size() == taetl::size_t(4));
    REQUIRE(t_string.length() == taetl::size_t(4));
    REQUIRE(t_string[0] == 'C');
    REQUIRE(t_string[1] == '-');
    REQUIRE(t_string[2] == 's');
    REQUIRE(t_string[3] == 't');
    REQUIRE(t_string[4] == char(0));
    REQUIRE(t_string.at(4) == char(0));

    // APPEND 5X SAME CHARACTER
    t_string.append(5, 'a');
    const char& first_char  = t_string[0];
    const char& second_char = t_string.at(1);

    REQUIRE(t_string.empty() == false);
    REQUIRE(t_string.capacity() == taetl::size_t(16));
    REQUIRE(t_string.size() == taetl::size_t(9));
    REQUIRE(t_string.length() == taetl::size_t(9));
    REQUIRE(first_char == 'C');
    REQUIRE(t_string[0] == 'C');
    REQUIRE(second_char == '-');
    REQUIRE(t_string[1] == '-');
    REQUIRE(t_string[2] == 's');
    REQUIRE(t_string[3] == 't');
    REQUIRE(t_string[4] == 'a');
    REQUIRE(t_string[5] == 'a');
    REQUIRE(t_string[6] == 'a');
    REQUIRE(t_string[7] == 'a');
    REQUIRE(t_string[8] == 'a');
    REQUIRE(t_string[9] == char(0));
    REQUIRE(t_string.at(9) == char(0));
}

TEST_CASE("string: algorithms", "[string]")
{
    // Create array with capacity of 16 and size of 0
    taetl::String<char, 16> t_string {};
    t_string.append(5, 'a');

    // APPLY ALGORITHM
    taetl::for_each(t_string.begin(), t_string.end(), [](auto& c) { c++; });
    REQUIRE(t_string.at(0) == 'b');
    REQUIRE(t_string.at(1) == 'b');
    REQUIRE(t_string.at(2) == 'b');
    REQUIRE(t_string.at(3) == 'b');
    REQUIRE(t_string.at(4) == 'b');
    REQUIRE(t_string.front() == 'b');
    REQUIRE(t_string.back() == 'b');
}

TEST_CASE("string: clear", "[string]")
{
    taetl::String<char, 16> t_string {};
    t_string.append(5, 'a');
    REQUIRE(t_string.empty() == false);

    t_string.clear();
    REQUIRE(t_string.capacity() == taetl::size_t(16));
    REQUIRE(t_string.empty() == true);
    REQUIRE(t_string.size() == taetl::size_t(0));
}
