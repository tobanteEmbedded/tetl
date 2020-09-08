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
#include "etl/iterator.hpp"
#include "etl/numeric.hpp"
#include "etl/vector.hpp"

#include "catch2/catch.hpp"

TEMPLATE_TEST_CASE("algorithm: for_each", "[algorithm]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    etl::stack_vector<TestType, 16> vec;
    vec.push_back(TestType(1));
    vec.push_back(TestType(2));
    vec.push_back(TestType(3));
    vec.push_back(TestType(4));

    // Check how often for_each calls the unary function
    int counter {};
    auto increment_counter = [&counter](auto& /*unused*/) { counter += 1; };

    // for_each
    etl::for_each(vec.begin(), vec.end(), increment_counter);
    REQUIRE(counter == 4);

    // for_each_n
    counter = 0;
    etl::for_each_n(vec.begin(), 2, increment_counter);
    REQUIRE(counter == 2);
}

TEMPLATE_TEST_CASE("algorithm: find", "[algorithm]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    etl::stack_vector<TestType, 16> vec;
    vec.push_back(TestType(1));
    vec.push_back(TestType(2));
    vec.push_back(TestType(3));
    vec.push_back(TestType(4));

    const auto* result1 = etl::find(vec.cbegin(), vec.cend(), TestType(3));
    REQUIRE_FALSE(result1 == vec.cend());

    auto* result2 = etl::find(vec.begin(), vec.end(), TestType(5));
    REQUIRE(result2 == vec.end());
}

TEMPLATE_TEST_CASE("algorithm: find_if", "[algorithm]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t)
{
    etl::stack_vector<TestType, 16> vec;
    vec.push_back(TestType(1));
    vec.push_back(TestType(2));
    vec.push_back(TestType(3));
    vec.push_back(TestType(4));

    // find_if
    auto* result3 = etl::find_if(
        vec.begin(), vec.end(), [](auto& x) -> bool { return static_cast<bool>(x % 2); });
    REQUIRE_FALSE(result3 == vec.end());

    auto* result4 = etl::find_if(vec.begin(), vec.end(), [](auto& x) -> bool {
        return static_cast<bool>(x == 100);
    });
    REQUIRE(result4 == vec.end());
}

TEMPLATE_TEST_CASE("algorithm: find_if_not", "[algorithm]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t)
{
    etl::stack_vector<TestType, 16> vec;
    vec.push_back(TestType(1));
    vec.push_back(TestType(2));
    vec.push_back(TestType(3));
    vec.push_back(TestType(4));
    // find_if_not
    auto* result5 = etl::find_if_not(
        vec.begin(), vec.end(), [](auto& x) -> bool { return static_cast<bool>(x % 2); });
    REQUIRE_FALSE(result5 == vec.end());

    auto* result6 = etl::find_if_not(vec.begin(), vec.end(), [](auto& x) -> bool {
        return static_cast<bool>(x == 100);
    });
    REQUIRE_FALSE(result6 == vec.end());

    auto* result7 = etl::find_if_not(vec.begin(), vec.end(), [](auto& x) -> bool {
        return static_cast<bool>(x != 100);
    });
    REQUIRE(result7 == vec.end());
}

TEMPLATE_TEST_CASE("algorithm: max", "[algorithm]", etl::int8_t, etl::int16_t,
                   etl::int32_t, etl::int64_t, float, double, long double)
{
    REQUIRE(etl::max<TestType>(1, 5) == 5);
    REQUIRE(etl::max<TestType>(-10, 5) == 5);
    REQUIRE(etl::max<TestType>(-10, -20) == -10);

    // Compare absolute values
    auto cmp = [](auto x, auto y) {
        auto new_x = x;
        auto new_y = y;
        if (x < 0) { new_x = new_x * -1; }
        if (y < 0) { new_y = new_y * -1; }

        return (new_x < new_y) ? y : x;
    };
    REQUIRE(etl::max<TestType>(-10, -20, cmp) == -20);
    REQUIRE(etl::max<TestType>(10, -20, cmp) == -20);
}

TEMPLATE_TEST_CASE("algorithm: max_element", "[algorithm]", etl::int8_t, etl::int16_t,
                   etl::int32_t, etl::int64_t, float, double, long double)
{
    etl::stack_vector<TestType, 16> vec;
    vec.push_back(TestType(1));
    vec.push_back(TestType(2));
    vec.push_back(TestType(3));
    vec.push_back(TestType(4));
    vec.push_back(TestType(-5));

    auto const functor
        = [](auto a, auto b) -> bool { return (etl::abs(a) < etl::abs(b)); };

    REQUIRE(*etl::max_element(vec.begin(), vec.end()) == TestType(4));
    REQUIRE(*etl::max_element(vec.begin(), vec.end(), functor) == TestType(-5));
}

TEMPLATE_TEST_CASE("algorithm: min", "[algorithm]", etl::int8_t, etl::int16_t,
                   etl::int32_t, etl::int64_t, float, double, long double)
{
    REQUIRE(etl::min<TestType>(1, 5) == 1);
    REQUIRE(etl::min<TestType>(-10, 5) == -10);
    REQUIRE(etl::min<TestType>(-10, -20) == -20);

    // Compare absolute values
    auto cmp = [](auto x, auto y) { return (etl::abs(x) < etl::abs(y)); };
    REQUIRE(etl::min<TestType>(-10, -20, cmp) == -10);
    REQUIRE(etl::min<TestType>(10, -20, cmp) == 10);
}

TEMPLATE_TEST_CASE("algorithm: min_element", "[algorithm]", etl::int8_t, etl::int16_t,
                   etl::int32_t, etl::int64_t, float, double, long double)
{
    etl::stack_vector<TestType, 16> vec;
    vec.push_back(TestType {1});
    vec.push_back(TestType {2});
    vec.push_back(TestType {3});
    vec.push_back(TestType {4});
    vec.push_back(TestType {-5});

    auto const functor
        = [](auto a, auto b) -> bool { return (etl::abs(a) < etl::abs(b)); };

    REQUIRE(*etl::min_element(vec.begin(), vec.end()) == TestType {-5});
    REQUIRE(*etl::min_element(vec.begin(), vec.end(), functor) == TestType {1});
}

TEMPLATE_TEST_CASE("algorithm: clamp", "[algorithm]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    REQUIRE(etl::clamp<TestType>(55, 0, 20) == TestType {20});
    REQUIRE(etl::clamp<TestType>(55, 0, 100) == TestType {55});
    STATIC_REQUIRE(etl::clamp<TestType>(55, 0, 20) == TestType {20});
    STATIC_REQUIRE(etl::clamp<TestType>(55, 0, 100) == TestType {55});
}

TEMPLATE_TEST_CASE("algorithm: all_of", "[algorithm]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    etl::stack_vector<TestType, 16> vec;
    vec.push_back(1);
    vec.push_back(2);
    vec.push_back(3);
    vec.push_back(4);

    SECTION("true")
    {
        auto const predicate = [](auto a) { return etl::abs(a) > 0; };
        REQUIRE(etl::all_of(vec.begin(), vec.end(), predicate) == true);
    }

    SECTION("false")
    {
        auto const predicate = [](auto a) { return etl::abs(a) > 10; };
        REQUIRE(etl::all_of(vec.begin(), vec.end(), predicate) == false);
    }
}

TEMPLATE_TEST_CASE("algorithm: any_of", "[algorithm]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    etl::stack_vector<TestType, 16> vec;
    vec.push_back(1);
    vec.push_back(2);
    vec.push_back(3);
    vec.push_back(4);

    SECTION("true")
    {
        auto const predicate = [](auto a) { return etl::abs(a) > 0; };
        REQUIRE(etl::any_of(vec.begin(), vec.end(), predicate) == true);
    }

    SECTION("false")
    {
        auto const predicate = [](auto a) { return etl::abs(a) > 10; };
        REQUIRE(etl::any_of(vec.begin(), vec.end(), predicate) == false);
    }
}

TEMPLATE_TEST_CASE("algorithm: none_of", "[algorithm]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    etl::stack_vector<TestType, 16> vec;
    vec.push_back(1);
    vec.push_back(2);
    vec.push_back(3);
    vec.push_back(4);

    SECTION("true")
    {
        auto const predicate = [](auto a) { return etl::abs(a) > 10; };
        REQUIRE(etl::none_of(vec.begin(), vec.end(), predicate) == true);
    }

    SECTION("false")
    {
        auto const predicate = [](auto a) { return a < 10; };
        REQUIRE(etl::none_of(vec.begin(), vec.end(), predicate) == false);
    }
}

TEMPLATE_TEST_CASE("algorithm: rotate", "[algorithm]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    etl::array<TestType, 16> arr;
    arr[0] = 1;
    arr[1] = 2;
    arr[2] = 3;
    arr[3] = 4;

    REQUIRE(arr[0] == 1);
    etl::rotate(arr.begin(), arr.begin() + 1, arr.end());
    REQUIRE(arr[0] == 2);
}

TEMPLATE_TEST_CASE("algorithm: stable_partition", "[algorithm]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    etl::array<TestType, 6> arr;
    arr[0] = 0;
    arr[1] = 1;
    arr[2] = 0;
    arr[3] = 2;
    arr[4] = 3;
    arr[5] = 4;

    REQUIRE(arr[0] == 0);
    etl::stable_partition(arr.begin(), arr.end(), [](auto n) { return n > 0; });
    REQUIRE(arr[0] == 1);
    REQUIRE(arr[1] == 2);
    REQUIRE(arr[2] == 3);
    REQUIRE(arr[3] == 4);
}

TEMPLATE_TEST_CASE("algorithm: copy", "[algorithm]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    using vector_t = etl::stack_vector<TestType, 4>;

    auto source = etl::array<TestType, 4> {};
    source[0]   = TestType {1};
    source[1]   = TestType {2};
    source[2]   = TestType {3};
    source[3]   = TestType {4};

    SECTION("copy to c array")
    {
        TestType dest[4] = {};
        etl::copy(begin(source), end(source), etl::begin(dest));
        REQUIRE(dest[0] == TestType {1});
        REQUIRE(dest[1] == TestType {2});
        REQUIRE(dest[2] == TestType {3});
        REQUIRE(dest[3] == TestType {4});
    }

    SECTION("copy to vector")
    {
        auto dest = vector_t {};
        REQUIRE(dest.size() == 0);
        etl::copy(begin(source), end(source), etl::back_inserter(dest));
        REQUIRE(dest.size() == 4);
        REQUIRE(dest.at(0) == TestType {1});
        REQUIRE(dest.at(1) == TestType {2});
        REQUIRE(dest.at(2) == TestType {3});
        REQUIRE(dest.at(3) == TestType {4});
    }
}

TEMPLATE_TEST_CASE("algorithm: copy_if", "[algorithm]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    using vector_t = etl::stack_vector<TestType, 4>;

    auto source = etl::array<TestType, 4> {};
    source[0]   = TestType {1};
    source[1]   = TestType {7};
    source[2]   = TestType {3};
    source[3]   = TestType {9};

    auto predicate = [](auto const& val) { return static_cast<int>(val) >= 5; };

    SECTION("copy_if to c array")
    {
        TestType dest[4] = {};
        auto res = etl::copy_if(begin(source), end(source), etl::begin(dest), predicate);
        REQUIRE(res == &dest[2]);
        REQUIRE(dest[0] == TestType {7});
        REQUIRE(dest[1] == TestType {9});
        REQUIRE(dest[2] == TestType {0});
        REQUIRE(dest[3] == TestType {0});
    }

    SECTION("copy_if to vector")
    {
        auto dest = vector_t {};
        REQUIRE(dest.size() == 0);
        etl::copy_if(begin(source), end(source), etl::back_inserter(dest), predicate);
        REQUIRE(dest.size() == 2);
        REQUIRE(dest.at(0) == TestType {7});
        REQUIRE(dest.at(1) == TestType {9});
    }
}
