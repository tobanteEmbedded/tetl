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

#include "etl/algorithm.hpp"
#include "etl/vector.hpp"

#include "catch2/catch.hpp"

TEMPLATE_TEST_CASE("vector: ConstructDefault", "[vector]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)
{
    etl::make::vector<TestType, 16> vec;

    REQUIRE(vec.empty() == true);
    REQUIRE(vec.size() == 0);
    REQUIRE(vec.max_size() == 16);
    REQUIRE(vec.capacity() == 16);
    REQUIRE(vec.data() != nullptr);

    auto func = [](etl::vector<TestType> const& v) {
        REQUIRE(v.empty() == true);
        REQUIRE(v.size() == 0);
        REQUIRE(v.max_size() == 16);
        REQUIRE(v.capacity() == 16);
        REQUIRE(v.data() != nullptr);
    };

    func(vec);
}

TEMPLATE_TEST_CASE("vector: RangeBasedFor", "[vector]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)
{
    etl::make::vector<TestType, 5> vec;
    vec.push_back(1);
    vec.push_back(2);
    vec.push_back(3);
    vec.push_back(4);
    vec.push_back(5);

    auto counter = 0;
    for (auto const& item : vec)
    { REQUIRE(item == static_cast<TestType>(++counter)); }
}

TEMPLATE_TEST_CASE("vector: Iterators", "[vector]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    etl::make::vector<TestType, 5> vec;
    vec.push_back(1);
    vec.push_back(2);
    vec.push_back(3);
    vec.push_back(4);
    vec.push_back(5);

    auto counter = 0;
    etl::for_each(vec.begin(), vec.end(), [&counter](auto const& item) {
        REQUIRE(item == static_cast<TestType>(++counter));
    });
}

TEMPLATE_TEST_CASE("vector: PushBack", "[vector]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    etl::make::vector<TestType, 2> vec;

    REQUIRE(vec.empty() == true);
    REQUIRE(vec.size() == 0);
    REQUIRE(vec.max_size() == 2);
    REQUIRE(vec.capacity() == 2);
    REQUIRE(vec.data() != nullptr);

    vec.push_back(TestType {1});
    REQUIRE(vec.empty() == false);
    REQUIRE(vec.size() == 1);
    REQUIRE(vec.max_size() == 2);
    REQUIRE(vec.capacity() == 2);
    REQUIRE(vec.data() != nullptr);

    vec.push_back(TestType {2});
    REQUIRE(vec.empty() == false);
    REQUIRE(vec.size() == 2);
    REQUIRE(vec.max_size() == 2);
    REQUIRE(vec.capacity() == 2);
    REQUIRE(vec.data() != nullptr);
}

TEMPLATE_TEST_CASE("vector: PopBack", "[vector]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    etl::make::vector<TestType, 5> vec;
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

TEMPLATE_TEST_CASE("vector: EmplaceBack", "[vector]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    etl::make::vector<TestType, 4> vec;
    REQUIRE(vec.empty() == true);
    REQUIRE(vec.size() == 0);

    vec.emplace_back(TestType {1});
    REQUIRE(vec.empty() == false);
    REQUIRE(vec.size() == 1);
    REQUIRE(vec.back() == 1);

    vec.emplace_back(TestType {2});
    REQUIRE(vec.size() == 2);
    REQUIRE(vec.back() == 2);
}