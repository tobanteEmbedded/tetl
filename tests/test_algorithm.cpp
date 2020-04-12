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

// TAETL
#include "taetl/algorithm.hpp"
#include "taetl/array.hpp"
#include "taetl/numeric.hpp"

#include "catch2/catch.hpp"

TEST_CASE("algorithm: for_each", "[algorithm]")
{
    taetl::Array<double, 16> t_array;

    // Add elements to the back
    t_array.push_back(1.0);
    t_array.push_back(2.0);
    t_array.push_back(3.0);
    t_array.push_back(4.0);

    // Check how often for_each calls the unary function
    int counter {};
    auto increment_counter = [&counter](auto&) { counter += 1; };

    // for_each
    taetl::for_each(t_array.begin(), t_array.end(), increment_counter);
    REQUIRE(counter == 4);

    // for_each_n
    counter = 0;
    taetl::for_each_n(t_array.begin(), 2, increment_counter);
    REQUIRE(counter == 2);
}

TEST_CASE("algorithm: find", "[algorithm]")
{
    taetl::Array<int, 16> t_array_2;
    // Add elements to the back
    t_array_2.push_back(1);
    t_array_2.push_back(2);
    t_array_2.push_back(3);
    t_array_2.push_back(4);

    auto result1 = taetl::find(t_array_2.cbegin(), t_array_2.cend(), 3);
    REQUIRE_FALSE(result1 == t_array_2.cend());

    auto result2 = taetl::find(t_array_2.begin(), t_array_2.end(), 5);
    REQUIRE(result2 == t_array_2.end());
}

TEST_CASE("algorithm: find_if", "[algorithm]")
{
    taetl::Array<int, 16> t_array_2;
    // Add elements to the back
    t_array_2.push_back(1);
    t_array_2.push_back(2);
    t_array_2.push_back(3);
    t_array_2.push_back(4);
    // find_if
    auto result3
        = taetl::find_if(t_array_2.begin(), t_array_2.end(),
                         [](auto& x) -> bool { return x % 2 ? true : false; });
    REQUIRE_FALSE(result3 == t_array_2.end());

    auto result4 = taetl::find_if(
        t_array_2.begin(), t_array_2.end(),
        [](auto& x) -> bool { return x == 100 ? true : false; });
    REQUIRE(result4 == t_array_2.end());
}
TEST_CASE("algorithm: find_if_not", "[algorithm]")
{
    taetl::Array<int, 16> t_array_2;
    // Add elements to the back
    t_array_2.push_back(1);
    t_array_2.push_back(2);
    t_array_2.push_back(3);
    t_array_2.push_back(4);
    // find_if_not
    auto result5 = taetl::find_if_not(
        t_array_2.begin(), t_array_2.end(),
        [](auto& x) -> bool { return x % 2 ? true : false; });
    REQUIRE_FALSE(result5 == t_array_2.end());

    auto result6 = taetl::find_if_not(
        t_array_2.begin(), t_array_2.end(),
        [](auto& x) -> bool { return x == 100 ? true : false; });
    REQUIRE_FALSE(result6 == t_array_2.end());

    auto result7 = taetl::find_if_not(
        t_array_2.begin(), t_array_2.end(),
        [](auto& x) -> bool { return x != 100 ? true : false; });
    REQUIRE(result7 == t_array_2.end());
}

TEST_CASE("algorithm: max", "[algorithm]")
{
    REQUIRE(taetl::max(1, 5) == 5);
    REQUIRE(taetl::max(-10, 5) == 5);
    REQUIRE(taetl::max(-10, -20) == -10);

    // Compare absolute values
    auto cmp = [](auto x, auto y) {
        auto new_x = x;
        auto new_y = y;
        if (x < 0) new_x = new_x * -1;
        if (y < 0) new_y = new_y * -1;

        return (new_x < new_y) ? y : x;
    };
    REQUIRE(taetl::max(-10, -20, cmp) == -20);
    REQUIRE(taetl::max(10, -20, cmp) == -20);
}

TEST_CASE("algorithm: max_element", "[algorithm]")
{
    taetl::Array<int, 16> arr1;
    arr1.push_back(1);
    arr1.push_back(2);
    arr1.push_back(3);
    arr1.push_back(4);
    arr1.push_back(-5);

    auto const functor = [](auto a, auto b) -> bool {
        return (taetl::abs(a) < taetl::abs(b));
    };

    REQUIRE(*taetl::max_element(arr1.begin(), arr1.end()) == 4);
    REQUIRE(*taetl::max_element(arr1.begin(), arr1.end(), functor) == -5);
}

TEST_CASE("algorithm: min", "[algorithm]")
{
    REQUIRE(taetl::min(1, 5) == 1);
    REQUIRE(taetl::min(-10, 5) == -10);
    REQUIRE(taetl::min(-10, -20) == -20);

    // Compare absolute values
    auto cmp = [](auto x, auto y) { return (taetl::abs(x) < taetl::abs(y)); };
    REQUIRE(taetl::min(-10, -20, cmp) == -10);
    REQUIRE(taetl::min(10, -20, cmp) == 10);
}

TEST_CASE("algorithm: min_element", "[algorithm]")
{
    taetl::Array<int, 16> arr1;
    arr1.push_back(1);
    arr1.push_back(2);
    arr1.push_back(3);
    arr1.push_back(4);
    arr1.push_back(-5);

    auto const functor = [](auto a, auto b) -> bool {
        return (taetl::abs(a) < taetl::abs(b));
    };

    REQUIRE(*taetl::min_element(arr1.begin(), arr1.end()) == -5);
    REQUIRE(*taetl::min_element(arr1.begin(), arr1.end(), functor) == 1);
}

TEST_CASE("algorithm: clamp", "[algorithm]")
{
    REQUIRE(taetl::clamp(55, 0, 20) == 20);
    REQUIRE(taetl::clamp(55, 0, 100) == 55);
}

TEST_CASE("algorithm: all_of", "[algorithm]")
{
    taetl::Array<int, 16> input;
    input.push_back(1);
    input.push_back(2);
    input.push_back(3);
    input.push_back(4);

    SECTION("true")
    {
        auto const predicate = [](auto a) { return taetl::abs(a) > 0; };
        REQUIRE(taetl::all_of(input.begin(), input.end(), predicate) == true);
    }

    SECTION("false")
    {
        auto const predicate = [](auto a) { return taetl::abs(a) > 10; };
        REQUIRE(taetl::all_of(input.begin(), input.end(), predicate) == false);
    }
}

TEST_CASE("algorithm: any_of", "[algorithm]")
{
    taetl::Array<int, 16> input;
    input.push_back(1);
    input.push_back(2);
    input.push_back(3);
    input.push_back(4);

    SECTION("true")
    {
        auto const predicate = [](auto a) { return taetl::abs(a) > 0; };
        REQUIRE(taetl::any_of(input.begin(), input.end(), predicate) == true);
    }

    SECTION("false")
    {
        auto const predicate = [](auto a) { return taetl::abs(a) > 10; };
        REQUIRE(taetl::any_of(input.begin(), input.end(), predicate) == false);
    }
}

TEST_CASE("algorithm: none_of", "[algorithm]")
{
    taetl::Array<int, 16> input;
    input.push_back(1);
    input.push_back(2);
    input.push_back(3);
    input.push_back(4);

    SECTION("true")
    {
        auto const predicate = [](auto a) { return taetl::abs(a) > 10; };
        REQUIRE(taetl::none_of(input.begin(), input.end(), predicate) == true);
    }

    SECTION("false")
    {
        auto const predicate = [](auto a) { return a < 10; };
        REQUIRE(taetl::none_of(input.begin(), input.end(), predicate) == false);
    }
}