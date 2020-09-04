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

#include "etl/string_view.hpp"

TEST_CASE("string_view: construct default", "[string_view]")
{
    constexpr auto sv = etl::string_view {};

    REQUIRE(sv.data() == nullptr);
    STATIC_REQUIRE(sv.data() == nullptr);

    REQUIRE(sv.size() == 0);
    STATIC_REQUIRE(sv.size() == 0);

    REQUIRE(sv.length() == 0);
    STATIC_REQUIRE(sv.length() == 0);
}

TEST_CASE("string_view: construct copy", "[string_view]")
{
    WHEN("empty")
    {
        auto const sv1 = etl::string_view {};
        auto const sv2 = sv1;

        REQUIRE(sv2.data() == nullptr);
        REQUIRE(sv2.size() == 0);
        REQUIRE(sv2.length() == 0);
    }

    WHEN("not empty")
    {
        auto const sv1 = etl::string_view {"test"};
        auto const sv2 = sv1;

        REQUIRE_FALSE(sv2.data() == nullptr);
        REQUIRE(sv2.size() == 4);
        REQUIRE(sv2.length() == 4);
    }
}

TEST_CASE("string_view: begin", "[string_view]")
{
    WHEN("empty")
    {
        auto const sv = etl::string_view {};
        REQUIRE(sv.data() == nullptr);
        REQUIRE(sv.begin() == sv.cbegin());
    }

    WHEN("not empty")
    {
        auto const sv = etl::string_view {"test"};
        REQUIRE(*sv.begin() == 't');
        REQUIRE(sv.begin() == sv.cbegin());
    }
}

TEST_CASE("string_view: end", "[string_view]")
{
    WHEN("empty")
    {
        auto const sv = etl::string_view {};
        REQUIRE(sv.data() == nullptr);
        REQUIRE(sv.end() == sv.cend());
    }

    WHEN("not empty")
    {
        auto const sv = etl::string_view {"test"};
        REQUIRE(sv.end() == sv.begin() + 4);
        REQUIRE(sv.end() == sv.cend());
    }
}

TEST_CASE("string_view: ranged-for", "[string_view]")
{
    auto const sv = etl::string_view {"test"};
    auto counter  = etl::string_view::size_type {0};
    for (auto c : sv)
    {
        etl::ignore_unused(c);
        counter++;
    }

    REQUIRE(counter == sv.size());
    REQUIRE(counter == 4);
}

TEST_CASE("string_view: at", "[string_view]")
{
    auto const sv1 = etl::string_view {"test"};
    REQUIRE(sv1.at(0) == 't');
    REQUIRE(sv1.at(1) == 'e');
    REQUIRE(sv1.at(2) == 's');
    REQUIRE(sv1.at(3) == 't');

    auto sv2 = etl::string_view {"tobi"};
    REQUIRE(sv2.at(0) == 't');
    REQUIRE(sv2.at(1) == 'o');
    REQUIRE(sv2.at(2) == 'b');
    REQUIRE(sv2.at(3) == 'i');
}

TEST_CASE("string_view: operator[]", "[string_view]")
{
    auto const sv1 = etl::string_view {"test"};
    REQUIRE(sv1[0] == 't');
    REQUIRE(sv1[1] == 'e');
    REQUIRE(sv1[2] == 's');
    REQUIRE(sv1[3] == 't');

    auto sv2 = etl::string_view {"tobi"};
    REQUIRE(sv2[0] == 't');
    REQUIRE(sv2[1] == 'o');
    REQUIRE(sv2[2] == 'b');
    REQUIRE(sv2[3] == 'i');
}

TEST_CASE("string_view: front", "[string_view]")
{
    auto const sv1 = etl::string_view {"test"};
    REQUIRE(sv1.front() == 't');

    auto sv2 = etl::string_view {"abc"};
    REQUIRE(sv2.front() == 'a');
}

TEST_CASE("string_view: back", "[string_view]")
{
    auto const sv1 = etl::string_view {"test"};
    REQUIRE(sv1.back() == 't');

    auto sv2 = etl::string_view {"abc"};
    REQUIRE(sv2.back() == 'c');
}

TEST_CASE("string_view: max_size", "[string_view]")
{
    auto const sv = etl::string_view {"test"};
    REQUIRE(sv.max_size() == etl::string_view::size_type(-1));
}

TEST_CASE("string_view: empty", "[string_view]")
{
    auto const t = etl::string_view {};
    REQUIRE(t.empty());

    auto const f = etl::string_view {"test"};
    REQUIRE_FALSE(f.empty());
}

TEST_CASE("string_view: remove_prefix", "[string_view]")
{
    WHEN("empty")
    {
        auto sv = etl::string_view {};
        REQUIRE(sv.empty());
        sv.remove_prefix(0);
        REQUIRE(sv.empty());
    }

    WHEN("not empty")
    {
        auto sv = etl::string_view {"test"};
        REQUIRE(sv.size() == 4);
        sv.remove_prefix(1);
        REQUIRE(sv.size() == 3);
        REQUIRE(sv.at(0) == 'e');
    }
}

TEST_CASE("string_view: remove_suffix", "[string_view]")
{
    WHEN("empty")
    {
        auto sv = etl::string_view {};
        REQUIRE(sv.empty());
        sv.remove_suffix(0);
        REQUIRE(sv.empty());
    }

    WHEN("not empty")
    {
        auto sv = etl::string_view {"test"};
        REQUIRE(sv.size() == 4);

        sv.remove_suffix(1);
        REQUIRE(sv.size() == 3);
        REQUIRE(sv.at(0) == 't');
        REQUIRE(sv.at(1) == 'e');
        REQUIRE(sv.at(2) == 's');

        sv.remove_suffix(2);
        REQUIRE(sv.size() == 1);
        REQUIRE(sv.at(0) == 't');
    }
}

TEST_CASE("string_view: copy", "[string_view]")
{
    WHEN("offset = 0")
    {
        char buffer[4] = {};
        auto sv        = etl::string_view {"test"};
        REQUIRE(sv.copy(&buffer[0], 2, 0) == 2);
        REQUIRE(buffer[0] == 't');
        REQUIRE(buffer[1] == 'e');
        REQUIRE(buffer[2] == 0);
        REQUIRE(buffer[3] == 0);
    }

    WHEN("offset = 1")
    {
        char buffer[4] = {};
        auto sv        = etl::string_view {"test"};
        REQUIRE(sv.copy(&buffer[0], 2, 1) == 2);
        REQUIRE(buffer[0] == 'e');
        REQUIRE(buffer[1] == 's');
        REQUIRE(buffer[2] == 0);
        REQUIRE(buffer[3] == 0);
    }

    WHEN("offset = 3")
    {
        char buffer[4] = {};
        auto sv        = etl::string_view {"test"};
        REQUIRE(sv.copy(&buffer[0], 2, 3) == 1);
        REQUIRE(buffer[0] == 't');
        REQUIRE(buffer[1] == 0);
        REQUIRE(buffer[2] == 0);
        REQUIRE(buffer[3] == 0);
    }
}

TEST_CASE("string_view: substr", "[string_view]")
{
    auto const sv = etl::string_view {"test"};

    auto const sub1 = sv.substr(0, 1);
    REQUIRE(sub1.size() == 1);
    REQUIRE(sub1.at(0) == 't');

    auto const sub2 = sv.substr(0, 2);
    REQUIRE(sub2.size() == 2);
    REQUIRE(sub2.at(0) == 't');
    REQUIRE(sub2.at(1) == 'e');

    auto const sub3 = sv.substr(2, 2);
    REQUIRE(sub3.size() == 2);
    REQUIRE(sub3.at(0) == 's');
    REQUIRE(sub3.at(1) == 't');
}

TEST_CASE("string_view: operotr==", "[string_view]")
{
    auto const sv = etl::string_view {"test"};
    REQUIRE(sv == sv);
    REQUIRE(sv == etl::string_view {"test"});
    REQUIRE_FALSE(sv != sv);
    REQUIRE_FALSE(sv != etl::string_view {"test"});

    REQUIRE(sv != sv.substr(0, 1));
    REQUIRE(sv != etl::string_view {"abc"});
    REQUIRE_FALSE(sv == sv.substr(0, 1));
    REQUIRE_FALSE(sv == etl::string_view {"abc"});
}
