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

    static_assert(arr_empty.empty() == true, "Array empty");
    static_assert(arr_empty.size() == 0, "Array size");
    static_assert(arr_empty.capacity() == 16, "Array capacity");

    constexpr auto arr1 = []() {
        taetl::Array<int, 16> arr {};
        arr.push_back(1);
        arr.push_back(2);
        arr.push_back(3);
        arr.push_back(4);
        return arr;
    }();

    static_assert(arr1.empty() == false, "Array empty");
    static_assert(arr1.size() == 4, "Array size");
    static_assert(arr1.capacity() == 16, "Array capacity");

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

        for (auto& item : arr)
        {
            item += 1;
        }
        return arr;
    }();

    static_assert(arr2.empty() == false, "Array empty");
    static_assert(arr2.size() == 8, "Array size");
    static_assert(arr2.capacity() == 8, "Array capacity");
}