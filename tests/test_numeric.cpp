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

#include "etl/array.hpp"        // for array
#include "etl/definitions.hpp"  // for int16_t, int32_t, int64_t, int8_t
#include "etl/limits.hpp"       // for numeric_limits
#include "etl/numeric.hpp"      // for midpoint, accumulate, gcd
#include "etl/vector.hpp"       // for stack_vector

#include "catch2/catch.hpp"

TEMPLATE_TEST_CASE("numeric: abs(integer)", "[numeric]", etl::int8_t, etl::int16_t,
                   etl::int32_t, etl::int64_t)
{
    REQUIRE(etl::abs<TestType>(0) == TestType {0});
    REQUIRE(etl::abs<TestType>(1) == TestType {1});
    REQUIRE(etl::abs<TestType>(-1) == TestType {1});
    REQUIRE(etl::abs<TestType>(10) == TestType {10});
    REQUIRE(etl::abs<TestType>(-10) == TestType {10});
}

TEMPLATE_TEST_CASE("numeric: abs(floating)", "[numeric]", float, double, long double)
{
    REQUIRE(etl::abs<TestType>(0.0) == TestType {0.0});
    REQUIRE(etl::abs<TestType>(1.0) == TestType {1.0});
    REQUIRE(etl::abs<TestType>(-1.0) == TestType {1.0});
    REQUIRE(etl::abs<TestType>(10.0) == TestType {10.0});
    REQUIRE(etl::abs<TestType>(-10.0) == TestType {10.0});
}

TEMPLATE_TEST_CASE("numeric: iota", "[numeric]", etl::int16_t, etl::int32_t, etl::int64_t,
                   etl::uint16_t, etl::uint32_t, etl::uint64_t, float, double,
                   long double)
{
    auto data = etl::array<TestType, 4> {};
    etl::iota(begin(data), end(data), TestType {0});
    REQUIRE(data[0] == 0);
    REQUIRE(data[1] == 1);
    REQUIRE(data[2] == 2);
    REQUIRE(data[3] == 3);
}

TEMPLATE_TEST_CASE("numeric: inner_product", "[numeric]", etl::int16_t, etl::int32_t,
                   etl::int64_t, etl::uint16_t, etl::uint32_t, etl::uint64_t, float,
                   double, long double)
{
    // 0 1 2 3 4
    etl::stack_vector<TestType, 6> a {};
    a.push_back(TestType {0});
    a.push_back(TestType {1});
    a.push_back(TestType {2});
    a.push_back(TestType {3});
    a.push_back(TestType {4});

    // 5 4 3 2 1
    etl::stack_vector<TestType, 6> b {};
    b.push_back(TestType {5});
    b.push_back(TestType {4});
    b.push_back(TestType {2});
    b.push_back(TestType {3});
    b.push_back(TestType {1});

    auto product = etl::inner_product(a.begin(), a.end(), b.begin(), TestType {0});
    REQUIRE(product == TestType {21});

    auto pairwise_matches = etl::inner_product(
        a.begin(), a.end(), b.begin(), TestType {0}, etl::plus<> {}, etl::equal_to<> {});
    REQUIRE(pairwise_matches == TestType {2});
}

TEMPLATE_TEST_CASE("numeric: partial_sum", "[numeric]", etl::int16_t, etl::int32_t,
                   etl::int64_t, etl::uint16_t, etl::uint32_t, etl::uint64_t, float,
                   double, long double)
{
    SECTION("plus")
    {
        etl::stack_vector<TestType, 5> vec {5, TestType {2}};
        etl::partial_sum(vec.begin(), vec.end(), vec.begin());
        REQUIRE(vec[0] == TestType {2});
        REQUIRE(vec[1] == TestType {4});
        REQUIRE(vec[2] == TestType {6});
        REQUIRE(vec[3] == TestType {8});
    }

    SECTION("multiplies (pow2)")
    {
        etl::stack_vector<TestType, 5> vec {5, TestType {2}};
        etl::partial_sum(vec.begin(), vec.end(), vec.begin(), etl::multiplies<>());
        REQUIRE(vec[0] == TestType {2});
        REQUIRE(vec[1] == TestType {4});
        REQUIRE(vec[2] == TestType {8});
        REQUIRE(vec[3] == TestType {16});
    }
}

TEMPLATE_TEST_CASE("numeric: accumulate", "[numeric]", etl::int16_t, etl::int32_t,
                   etl::int64_t, etl::uint16_t, etl::uint32_t, etl::uint64_t, float,
                   double, long double)
{
    etl::stack_vector<TestType, 16> vec;
    vec.push_back(1);
    vec.push_back(2);
    vec.push_back(3);
    vec.push_back(4);

    // accumulate
    REQUIRE(etl::accumulate(vec.begin(), vec.end(), TestType {0}) == 10);

    // accumulate binary function op
    auto func = [](TestType a, TestType b) { return a + (b * 2); };
    REQUIRE(etl::accumulate(vec.begin(), vec.end(), TestType {0}, func) == 20);
}

TEMPLATE_TEST_CASE("numeric: gcd", "[numeric]", etl::uint8_t, etl::int8_t, etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t)
{
    REQUIRE(etl::gcd(5, 10) == 5);
    REQUIRE(etl::gcd(10, 5) == 5);
    STATIC_REQUIRE(etl::gcd(10, 5) == 5);

    REQUIRE(etl::gcd(30, 105) == 15);
    REQUIRE(etl::gcd(105, 30) == 15);
    STATIC_REQUIRE(etl::gcd(105, 30) == 15);
}

TEMPLATE_TEST_CASE("numeric: midpoint(integer)", "[numeric]", signed char, signed short,
                   signed int, signed long)
{
    REQUIRE(etl::midpoint<TestType>(-3, -4) == -3);
    REQUIRE(etl::midpoint<TestType>(-4, -3) == -4);
    STATIC_REQUIRE(etl::midpoint<TestType>(-3, -4) == -3);
    STATIC_REQUIRE(etl::midpoint<TestType>(-4, -3) == -4);

    REQUIRE(etl::midpoint<TestType>(0, 2) == 1);
    REQUIRE(etl::midpoint<TestType>(2, 0) == 1);
    STATIC_REQUIRE(etl::midpoint<TestType>(0, 2) == 1);
    STATIC_REQUIRE(etl::midpoint<TestType>(2, 0) == 1);
}

TEMPLATE_TEST_CASE("numeric: midpoint(floating_point)", "[numeric]", float, double,
                   long double)
{
    using T = TestType;

    SECTION("normal")
    {
        constexpr T a = T(-3.0);
        constexpr T b = T(-4.0);
        REQUIRE(etl::midpoint(a, b) == T(-3.5));
        REQUIRE(etl::midpoint(b, a) == T(-3.5));
        STATIC_REQUIRE(etl::midpoint(a, b) == T(-3.5));
        STATIC_REQUIRE(etl::midpoint(b, a) == T(-3.5));
    }

    SECTION("small numbers")
    {
        auto const small = etl::numeric_limits<T>::min();
        REQUIRE(etl::midpoint(small, small) == small);
    }

    SECTION("large numbers")
    {
        auto const halfMax = etl::numeric_limits<T>::max() / TestType(2.0);
        auto const x       = halfMax + TestType(4.0);
        auto const y       = halfMax + TestType(8.0);
        REQUIRE(etl::midpoint(x, y) == halfMax + TestType(6.0));
    }

    SECTION("large negative numbers")
    {
        auto const halfMax = etl::numeric_limits<T>::max() / TestType(2.0);
        auto const x       = -halfMax + TestType(4.0);
        auto const y       = -halfMax + TestType(8.0);
        REQUIRE(etl::midpoint(x, y) == -halfMax + TestType(6.0));
    }
}

TEMPLATE_TEST_CASE("numeric: midpoint(pointer)", "[numeric]", char, short, int, long,
                   float, double)
{
    using T = TestType;

    SECTION("even")
    {
        constexpr T data[] = {T(1), T(2), T(3), T(4)};
        REQUIRE(*etl::midpoint(&data[0], &data[2]) == 2);
        REQUIRE(*etl::midpoint(&data[2], &data[0]) == 2);
        STATIC_REQUIRE(*etl::midpoint(&data[0], &data[2]) == 2);
        STATIC_REQUIRE(*etl::midpoint(&data[2], &data[0]) == 2);
    }

    SECTION("odd")
    {
        constexpr T data[] = {T(1), T(2), T(3), T(4), T(5)};
        REQUIRE(*etl::midpoint(&data[0], &data[3]) == T(2));
        STATIC_REQUIRE(*etl::midpoint(&data[0], &data[3]) == T(2));

        REQUIRE(*etl::midpoint(&data[3], &data[0]) == T(3));
        STATIC_REQUIRE(*etl::midpoint(&data[3], &data[0]) == T(3));
    }
}
