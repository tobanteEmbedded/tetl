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

#include "taetl/algorithm.hpp"
#include "taetl/vector.hpp"

#include "catch2/catch.hpp"

TEST_CASE("vector: ConstructDefault", "[vector]")
{
    taetl::make::vector<int, 16> vec;

    REQUIRE(vec.empty() == true);
    REQUIRE(vec.size() == 0);
    REQUIRE(vec.max_size() == 16);
    REQUIRE(vec.capacity() == 16);
    REQUIRE(vec.data() != nullptr);

    auto func = [](taetl::vector<int> const& v) {
        REQUIRE(v.empty() == true);
        REQUIRE(v.size() == 0);
        REQUIRE(v.max_size() == 16);
        REQUIRE(v.capacity() == 16);
        REQUIRE(v.data() != nullptr);
    };

    func(vec);
}

TEST_CASE("vector: RangeBasedFor", "[vector]")
{
    taetl::make::vector<int, 5> vec;
    vec.push_back(1);
    vec.push_back(2);
    vec.push_back(3);
    vec.push_back(4);
    vec.push_back(5);

    auto counter = 0;
    for (auto const& item : vec) { REQUIRE(item == ++counter); }
}

TEST_CASE("vector: Iterators", "[vector]")
{
    taetl::make::vector<int, 5> vec;
    vec.push_back(1);
    vec.push_back(2);
    vec.push_back(3);
    vec.push_back(4);
    vec.push_back(5);

    auto counter = 0;
    taetl::for_each(vec.begin(), vec.end(), [&counter](auto const& item) {
        REQUIRE(item == ++counter);
    });
}

TEST_CASE("vector: PushBack", "[vector]")
{
    taetl::make::vector<int, 2> vec;

    REQUIRE(vec.empty() == true);
    REQUIRE(vec.size() == 0);
    REQUIRE(vec.max_size() == 2);
    REQUIRE(vec.capacity() == 2);
    REQUIRE(vec.data() != nullptr);

    vec.push_back(1);
    REQUIRE(vec.empty() == false);
    REQUIRE(vec.size() == 1);
    REQUIRE(vec.max_size() == 2);
    REQUIRE(vec.capacity() == 2);
    REQUIRE(vec.data() != nullptr);

    vec.push_back(2);
    REQUIRE(vec.empty() == false);
    REQUIRE(vec.size() == 2);
    REQUIRE(vec.max_size() == 2);
    REQUIRE(vec.capacity() == 2);
    REQUIRE(vec.data() != nullptr);
}

TEST_CASE("vector: PopBack", "[vector]")
{
    taetl::make::vector<int, 5> vec;
    vec.push_back(1);
    vec.push_back(2);
    vec.push_back(3);
    vec.push_back(4);
    vec.push_back(5);

    REQUIRE(vec.back() == 5);
    vec.pop_back();
    REQUIRE(vec.back() == 4);
    vec.pop_back();
    REQUIRE(vec.back() == 3);
    vec.pop_back();
    REQUIRE(vec.back() == 2);
    vec.pop_back();
    REQUIRE(vec.back() == 1);
    vec.pop_back();

    REQUIRE(vec.empty());
}

TEST_CASE("vector: EmplaceBack", "[vector]")
{
    taetl::make::vector<int, 4> vec;
    REQUIRE(vec.empty() == true);
    REQUIRE(vec.size() == 0);

    vec.emplace_back(1);
    REQUIRE(vec.empty() == false);
    REQUIRE(vec.size() == 1);
    REQUIRE(vec.back() == 1);

    vec.emplace_back(2);
    REQUIRE(vec.size() == 2);
    REQUIRE(vec.back() == 2);
}