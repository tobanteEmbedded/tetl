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

#include "etl/array.hpp"

#include "catch2/catch.hpp"

TEMPLATE_TEST_CASE("array: construct default", "[array]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    etl::array<TestType, 2> arr {};

    REQUIRE(arr.empty() == false);
    REQUIRE(arr[0] == TestType {0});
    REQUIRE(arr[1] == TestType {0});
}

TEMPLATE_TEST_CASE("array: size", "[array]", etl::uint8_t, etl::int8_t, etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
    etl::array<TestType, 4> arr {};
    REQUIRE(arr.size() == arr.max_size());
    REQUIRE(arr.size() == 4);
}

TEMPLATE_TEST_CASE("array: range-for", "[array]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    etl::array<TestType, 4> arr {};
    arr[0] = 0;
    arr[1] = 1;
    arr[2] = 2;
    arr[3] = 3;

    auto counter = 0;
    for (auto& x : arr) { REQUIRE(x == static_cast<TestType>(counter++)); }
}

TEMPLATE_TEST_CASE("array: range-for-const", "[array]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    etl::array<TestType, 4> arr {};
    arr.at(0) = 0;
    arr.at(1) = 1;
    arr.at(2) = 2;
    arr.at(3) = 3;

    REQUIRE(*arr.data() == 0);
    REQUIRE(arr.front() == 0);
    REQUIRE(arr.back() == TestType {3});

    auto counter = 0;
    for (auto const& x : arr) { REQUIRE(x == static_cast<TestType>(counter++)); }
}

TEMPLATE_TEST_CASE("array: begin/end const", "[array]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    auto const arr = []() {
        etl::array<TestType, 4> a {};
        a.at(0) = 0;
        a.at(1) = 1;
        a.at(2) = 2;
        a.at(3) = 3;
        return a;
    }();

    REQUIRE(*arr.data() == 0);

    auto counter = 0;
    for (auto const& x : arr) { REQUIRE(x == static_cast<TestType>(counter++)); }
}

TEMPLATE_TEST_CASE("array: at", "[array]", etl::uint8_t, etl::int8_t, etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
    auto arr = []() {
        etl::array<TestType, 4> a {};
        a.at(0) = TestType {0};
        a.at(1) = TestType {1};
        a.at(2) = TestType {2};
        a.at(3) = TestType {3};
        return a;
    }();

    REQUIRE(arr.at(0) == TestType {0});
    REQUIRE(arr.at(1) == TestType {1});
    REQUIRE(arr.at(2) == TestType {2});
    REQUIRE(arr.at(3) == TestType {3});
}

TEMPLATE_TEST_CASE("array: at const", "[array]", etl::uint8_t, etl::int8_t, etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
    auto const arr = []() {
        etl::array<TestType, 4> a {};
        a.at(0) = 0;
        a.at(1) = 1;
        a.at(2) = 2;
        a.at(3) = 3;
        return a;
    }();

    REQUIRE(arr.at(0) == TestType {0});
    REQUIRE(arr.at(1) == TestType {1});
    REQUIRE(arr.at(2) == TestType {2});
    REQUIRE(arr.at(3) == TestType {3});
}

TEMPLATE_TEST_CASE("array: front/back", "[array]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    auto arr = []() {
        etl::array<TestType, 4> a {};
        a.at(0) = TestType {0};
        a.at(1) = TestType {1};
        a.at(2) = TestType {2};
        a.at(3) = TestType {3};
        return a;
    }();

    REQUIRE(arr.front() == 0);
    REQUIRE(arr.back() == 3);
}

TEMPLATE_TEST_CASE("array: front/back const", "[array]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    auto const arr = []() {
        etl::array<TestType, 4> a {};
        a.at(0) = TestType {0};
        a.at(1) = TestType {1};
        a.at(2) = TestType {2};
        a.at(3) = TestType {3};
        return a;
    }();

    REQUIRE(arr.front() == 0);
    REQUIRE(arr.back() == 3);
}
