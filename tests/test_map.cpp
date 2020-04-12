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

#include "catch2/catch.hpp"

template <class... Args>
auto IgnoreUnused(Args&&...) noexcept -> void
{
}

TEST_CASE("map: ConstructDefault", "[map]")
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
            IgnoreUnused(item);
            REQUIRE(false);
        }
    };

    func(test);
}

TEST_CASE("map: Insert", "[map]")
{
    taetl::make::map<int, int, 4> test {};

    auto func = [](taetl::map<int, int>& m) {
        REQUIRE(m.max_size() == 4);
        REQUIRE(m.empty() == true);
        REQUIRE(m.size() == 0);
        m.insert({1, 143});
        REQUIRE(m.max_size() == 4);
        REQUIRE(m.empty() == false);
        REQUIRE(m.size() == 1);
        REQUIRE(m.count(1) == 1);
    };

    func(test);
}