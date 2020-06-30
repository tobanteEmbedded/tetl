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

#include "taetl/map.hpp"
#include "taetl/warning.hpp"

#include "catch2/catch.hpp"

TEST_CASE("map: construct empty", "[map]")
{
    taetl::make::map<int, int, 4> test {};

    auto func = [](taetl::map<int, int> const& m) {
        REQUIRE(m.empty() == true);
        REQUIRE(m.size() == 0);
        REQUIRE(m.max_size() == 4);
        REQUIRE(m.find(1) == nullptr);
        REQUIRE(m.count(1) == 0);

        // there should be no elements
        for (auto const& item : m)
        {
            taetl::ignore_unused(item);
            REQUIRE(false);
        }
    };

    func(test);
}

TEST_CASE("map: insert(value_type const&)", "[map]")
{
    auto map        = taetl::make::map<int, int, 4> {};
    auto const pair = taetl::pair<int, int> {1, 143};
    map.insert(pair);
    REQUIRE(map.size() == 1);
    REQUIRE(map.count(1) == 1);
    REQUIRE(map.find(1)->second == 143);
}

TEST_CASE("map: insert(value_type &&)", "[map]")
{
    auto map = taetl::make::map<int, float, 4> {};
    map.insert(taetl::pair<int, float> {2, 143.0f});
    REQUIRE(map.size() == 1);
    REQUIRE(map.count(2) == 1);
    REQUIRE(map.find(2)->second == 143.0f);
}