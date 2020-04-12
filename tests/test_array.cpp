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

#include "taetl/array.hpp"

#include "catch2/catch.hpp"

TEST_CASE("array: construct default", "[array]")
{
    taetl::array<int, 2> arr {};

    REQUIRE(arr.empty() == false);
    REQUIRE(arr[0] == 0);
    REQUIRE(arr[1] == 0);
}

TEST_CASE("array: size", "[array]")
{
    taetl::array<int, 4> arr {};
    REQUIRE(arr.size() == arr.max_size());
    REQUIRE(arr.size() == 4);
}

TEST_CASE("array: range-for", "[array]")
{
    taetl::array<int, 4> arr {};
    arr[0] = 0;
    arr[1] = 1;
    arr[2] = 2;
    arr[3] = 3;

    auto counter = 0;
    for (auto& x : arr)
    {
        REQUIRE(x == counter++);
    }
}

TEST_CASE("array: range-for-const", "[array]")
{
    taetl::array<int, 4> arr {};
    arr.at(0) = 0;
    arr.at(1) = 1;
    arr.at(2) = 2;
    arr.at(3) = 3;

    auto counter = 0;
    for (auto const& x : arr)
    {
        REQUIRE(x == counter++);
    }
}

TEST_CASE("array: begin/end const", "[array]")
{
    auto const arr = []() {
        taetl::array<int, 4> a {};
        a.at(0) = 0;
        a.at(1) = 1;
        a.at(2) = 2;
        a.at(3) = 3;
        return a;
    }();

    auto counter = 0;
    for (auto const& x : arr)
    {
        REQUIRE(x == counter++);
    }

    REQUIRE(arr.at(0) == 0);
    REQUIRE(arr.at(1) == 1);
    REQUIRE(arr.at(2) == 2);
    REQUIRE(arr.at(3) == 3);
}
