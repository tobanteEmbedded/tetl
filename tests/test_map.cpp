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

#include "etl/map.hpp"
#include "etl/warning.hpp"

#include "catch2/catch.hpp"

TEST_CASE("map: construct", "[map]")
{
    etl::make::map<int, int, 4> test {};

    auto func = [](etl::map<int, int> const& m) {
        REQUIRE(m.empty() == true);
        REQUIRE(m.size() == 0);
        REQUIRE(m.max_size() == 4);
        REQUIRE(m.find(1) == nullptr);
        REQUIRE(m.count(1) == 0);

        // there should be no elements
        for (auto const& item : m)
        {
            etl::ignore_unused(item);
            REQUIRE(false);
        }
    };

    func(test);
}

TEST_CASE("map: at", "[map]")
{
    auto map = etl::make::map<int, int, 4> {};
    map.insert({1, 143});
    map.insert({2, 42});
    REQUIRE(map.at(1) == 143);
    REQUIRE(map.at(2) == 42);

    auto const map2 = map;
    REQUIRE(map2.at(1) == 143);
    REQUIRE(map2.at(2) == 42);
}

TEST_CASE("map: operator[]", "[map]")
{
    auto map = etl::make::map<int, int, 4> {};
    map.insert({1, 143});
    map.insert({2, 42});
    REQUIRE(map[1] == 143);
    REQUIRE(map[2] == 42);
    REQUIRE(map.contains(3) == false);
    REQUIRE(map[3] == 0);
    REQUIRE(map.contains(3) == true);
}

TEST_CASE("map: begin/cbegin", "[map]")
{
    auto m = etl::make::map<int, int, 4> {};
    m.insert({1, 143});
    REQUIRE(m.begin() == m.cbegin());
    REQUIRE(m.begin()->second == 143);
}

TEST_CASE("map: end/cend", "[map]")
{
    auto m = etl::make::map<int, int, 4> {};
    m.insert({1, 143});
    REQUIRE(m.end() == m.cend());
}

TEST_CASE("map: ranged-based-for", "[map]")
{
    WHEN("mutable")
    {
        auto m = etl::make::map<int, int, 4> {};
        m.insert({1, 143});
        m.insert({2, 143});
        m.insert({3, 143});

        auto result = 0;
        for (auto const& item : m) { result += item.second; }

        REQUIRE(result == 143 * 3);
    }

    WHEN("const")
    {
        auto const m = []() {
            auto r = etl::make::map<int, int, 4> {};
            r.insert({1, 42});
            r.insert({2, 42});
            r.insert({3, 42});
            r.insert({4, 42});
            return r;
        }();

        auto result = 0;
        for (auto const& item : m) { result += item.second; }

        REQUIRE(result == 42 * 4);
    }
}

TEST_CASE("map: empty", "[map]")
{
    auto map = etl::make::map<int, int, 4> {};
    REQUIRE(map.empty() == true);
    map.insert({1, 143});
    REQUIRE(map.empty() == false);
}

TEST_CASE("map: size", "[map]")
{
    auto map = etl::make::map<int, int, 4> {};
    REQUIRE(map.size() == 0);
    map.insert({1, 143});
    REQUIRE(map.size() == 1);
    map.insert({2, 143});
    REQUIRE(map.size() == 2);
    map.insert({3, 143});
    REQUIRE(map.size() == 3);
}

TEST_CASE("map: count/contains", "[map]")
{
    auto map = etl::make::map<int, int, 4> {};
    map.insert({1, 143});
    map.insert({2, 143});
    map.insert({3, 143});
    REQUIRE(map.contains(1) == true);
    REQUIRE(map.count(1) == 1);
    REQUIRE(map.contains(3) == true);
    REQUIRE(map.count(3) == 1);
    REQUIRE(map.contains(42) == false);
    REQUIRE(map.count(42) == 0);
}

TEST_CASE("map: clear", "[map]")
{
    auto map = etl::make::map<int, int, 4> {};
    map.insert({1, 143});
    map.insert({2, 143});
    map.insert({3, 143});
    REQUIRE(map.empty() == false);
    REQUIRE(map.size() == 3);
    REQUIRE(map.count(1) == 1);

    map.clear();
    REQUIRE(map.empty() == true);
    REQUIRE(map.size() == 0);
    REQUIRE(map.count(1) == 0);
}

TEST_CASE("map: insert(value_type const&)", "[map]")
{
    auto map  = etl::make::map<int, int, 4> {};
    auto pair = etl::pair<int, int> {1, 143};
    auto func = [&](auto const& p) {
        map.insert(p);
        REQUIRE(map.size() == 1);
        REQUIRE(map.count(1) == 1);
        REQUIRE(map.find(1)->second == 143);
    };

    func(pair);
}

TEST_CASE("map: insert(value_type &&)", "[map]")
{
    auto map = etl::make::map<int, float, 4> {};

    map.insert(etl::pair<int, float> {2, 143.0F});
    REQUIRE(map.size() == 1);
    REQUIRE(map.count(2) == 1);
    REQUIRE(map.find(2)->second == 143.0F);

    map.insert(etl::pair<int, float> {3, 42.0F});
    REQUIRE(map.size() == 2);
    REQUIRE(map.count(3) == 1);
    REQUIRE(map.find(3)->second == 42.0F);
}