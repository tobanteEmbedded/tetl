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

#include "taetl/array.hpp"

#include "catch2/catch.hpp"

TEST_CASE("array: constexpr", "[array]")
{
    // Create empty array
    constexpr auto arr_empty = []() {
        taetl::Array<int, 16> arr {};
        return arr;
    }();

    STATIC_REQUIRE(arr_empty.empty() == true);
    STATIC_REQUIRE(arr_empty.size() == 0);
    STATIC_REQUIRE(arr_empty.capacity() == 16);

    constexpr auto arr1 = []() {
        taetl::Array<int, 16> arr {};
        arr.push_back(1);
        arr.push_back(2);
        arr.push_back(3);
        arr.push_back(4);
        return arr;
    }();

    STATIC_REQUIRE(arr1.empty() == false);
    STATIC_REQUIRE(arr1.size() == 4);
    STATIC_REQUIRE(arr1.capacity() == 16);

    constexpr auto arr2 = []() {
        taetl::Array<int, 8> arr {};
        arr.push_back(1);
        arr.push_back(2);
        arr.push_back(3);
        arr.push_back(4);
        arr.push_back(5);
        arr.push_back(6);
        arr.push_back(7);
        arr.push_back(8);
        arr.push_back(9);  // Will fail silently.

        for (auto& item : arr) { item += 1; }
        return arr;
    }();

    STATIC_REQUIRE(arr2.empty() == false);
    STATIC_REQUIRE(arr2.size() == 8);
    STATIC_REQUIRE(arr2.capacity() == 8);
}