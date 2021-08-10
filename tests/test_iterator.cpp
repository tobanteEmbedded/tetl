// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.
#include "etl/iterator.hpp"

#include "etl/array.hpp"
#include "etl/string_view.hpp"
#include "etl/utility.hpp" // for as_const
#include "etl/vector.hpp"

#include <list>

#include "catch2/catch_template_test_macros.hpp"

TEMPLATE_TEST_CASE(
    "iterator: make_reverse_iterator", "[iterator]", char, int, float)
{
    using T   = TestType;
    auto data = etl::array { T(1), T(2), T(3) };
    CHECK(*data.rbegin() == *etl::make_reverse_iterator(data.end()));
}

TEMPLATE_TEST_CASE("iterator: rbegin", "[iterator]", char, int, float)
{
    using T = TestType;

    SECTION("C array")
    {
        T data[4] = { T(1), T(2), T(3), T(4) };
        CHECK(*etl::rbegin(data) == T(4));
        CHECK(*(++etl::rbegin(data)) == T(3));
    }

    SECTION("array")
    {
        auto data = etl::array { T(1), T(2), T(3), T(4) };
        CHECK(*etl::rbegin(data) == T(4));
        CHECK(*etl::rbegin(etl::as_const(data)) == T(4));
        CHECK(*etl::crbegin(data) == T(4));
        CHECK(*(++rbegin(data)) == T(3)); // Found via ADL
    }
}

TEMPLATE_TEST_CASE("iterator: rend", "[iterator]", char, int, float)
{
    using T = TestType;

    SECTION("C array")
    {
        T data[4] = { T(0), T(0), T(0), T(0) };
        auto cmp  = [](auto val) { return val == T(0); };
        CHECK(etl::all_of(etl::rbegin(data), etl::rend(data), cmp));
        CHECK(etl::all_of(etl::crbegin(data), etl::crend(data), cmp));
    }

    SECTION("array")
    {
        auto data = etl::array { T(0), T(0), T(0), T(0) };
        auto cmp  = [](auto val) { return val == T(0); };
        CHECK(etl::all_of(rbegin(data), rend(data), cmp));
        CHECK(etl::all_of(crbegin(data), crend(data), cmp));
        CHECK(etl::all_of(
            rbegin(etl::as_const(data)), rend(etl::as_const(data)), cmp));
    }
}

TEST_CASE("iterator: size", "[iterator]")
{
    int carr[4] = {};
    REQUIRE(etl::size(carr) == 4);

    auto arr = etl::array<int, 5> {};
    REQUIRE(etl::size(arr) == 5);

    auto sv1 = etl::string_view { "test" };
    REQUIRE(etl::size(sv1) == 4);

    auto const sv2 = etl::string_view {};
    REQUIRE(etl::size(sv2) == 0);
}

TEST_CASE("iterator: empty", "[iterator]")
{
    int carr[4] = {};
    REQUIRE_FALSE(etl::empty(carr));

    auto arr = etl::array<int, 5> {};
    REQUIRE_FALSE(etl::empty(arr));

    auto sv1 = etl::string_view { "test" };
    REQUIRE_FALSE(etl::empty(sv1));

    auto const sv2 = etl::string_view {};
    REQUIRE(etl::empty(sv2));
}

TEST_CASE("iterator: data", "[iterator]")
{
    int carr[4] = {};
    REQUIRE(etl::data(carr) != nullptr);

    auto arr = etl::array<int, 5> {};
    REQUIRE(etl::data(arr) != nullptr);

    auto sv1 = etl::string_view { "test" };
    REQUIRE(etl::data(sv1) != nullptr);

    auto const sv2 = etl::string_view {};
    REQUIRE(etl::data(sv2) == nullptr);
}

TEMPLATE_TEST_CASE("iterator: distance", "[iterator]", char, int, float)
{
    SECTION("random access iterator")
    {
        auto arr = etl::array<TestType, 5> {};
        REQUIRE(etl::distance(begin(arr), begin(arr)) == 0);
        REQUIRE(etl::distance(end(arr), end(arr)) == 0);
        REQUIRE(etl::distance(begin(arr), begin(arr) + 2) == 2);
        REQUIRE(etl::distance(begin(arr), end(arr)) == 5);
    }
}

TEMPLATE_TEST_CASE("iterator: advance", "[iterator]", char, int, float)
{
    SECTION("random access iterator")
    {
        auto arr = etl::array<TestType, 5> {};
        auto* p  = arr.begin();

        etl::advance(p, 1);
        REQUIRE(p != begin(arr));
        REQUIRE(p == &arr[1]);

        etl::advance(p, 2);
        REQUIRE(p == &arr[3]);
    }
}

TEMPLATE_TEST_CASE("iterator: next", "[iterator]", char, int, float)
{
    SECTION("random access iterator")
    {
        auto arr = etl::array<TestType, 5> {};
        auto* p  = arr.begin();
        auto* n1 = etl::next(p);
        REQUIRE(n1 != begin(arr));
        REQUIRE(n1 == &arr[1]);

        auto* n2 = etl::next(n1);
        REQUIRE(n2 != begin(arr));
        REQUIRE(n2 == &arr[2]);
    }
}

TEMPLATE_TEST_CASE("iterator: prev", "[iterator]", char, int, float)
{
    SECTION("random access iterator")
    {
        auto arr = etl::array<TestType, 5> {};
        auto* p  = arr.end();
        auto* n1 = etl::prev(p);
        REQUIRE(n1 != end(arr));
        REQUIRE(n1 == &arr[4]);

        auto* n2 = etl::prev(n1);
        REQUIRE(n2 != end(arr));
        REQUIRE(n2 == &arr[3]);
    }
}

TEMPLATE_TEST_CASE(
    "iterator: back_insert_iterator", "[iterator]", char, int, float)
{
    SECTION("insert rvalue")
    {
        auto vec  = etl::static_vector<TestType, 5> {};
        auto iter = etl::back_inserter(vec);
        REQUIRE(vec.size() == 0);
        iter = TestType { 1 };
        REQUIRE(vec.size() == 1);
    }

    SECTION("insert lvalue")
    {
        auto vec  = etl::static_vector<TestType, 5> {};
        auto iter = etl::back_inserter(vec);
        REQUIRE(vec.size() == 0);
        auto const val = TestType { 42 };
        iter           = val;
        REQUIRE(vec.size() == 1);
    }

    SECTION("increment/decrement/dereference should not change state (no-op)")
    {
        auto vec  = etl::static_vector<TestType, 5> {};
        auto iter = etl::back_inserter(vec);
        REQUIRE(vec.size() == 0);
        auto const val = TestType { 42 };
        iter           = val;
        REQUIRE(vec.size() == 1);
        REQUIRE(&++iter == &iter);
        REQUIRE(vec.size() == 1);
        *iter;
        REQUIRE(vec.size() == 1);
    }
}

TEMPLATE_TEST_CASE(
    "iterator: front_insert_iterator", "[iterator]", char, int, float)
{
    SECTION("construct")
    {
        auto vec  = etl::static_vector<TestType, 5> {};
        auto iter = etl::front_inserter(vec);
        REQUIRE(&++iter == &iter);
        REQUIRE(&++iter == &(*iter));
    }
}