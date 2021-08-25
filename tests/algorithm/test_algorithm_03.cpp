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

#include "etl/algorithm.hpp"

#include "etl/array.hpp"
#include "etl/cctype.hpp"
#include "etl/cstdint.hpp"
#include "etl/functional.hpp"
#include "etl/iterator.hpp"
#include "etl/numeric.hpp"
#include "etl/string.hpp"
#include "etl/vector.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEMPLATE_TEST_CASE("algorithm: binary_search", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;

    SECTION("empty range")
    {
        auto const data = etl::static_vector<T, 4> {};
        CHECK_FALSE(etl::binary_search(begin(data), end(data), T(0)));
    }

    SECTION("range")
    {
        auto const data = etl::array { T(0), T(1), T(2) };
        CHECK(etl::binary_search(begin(data), end(data), T(0)));
        CHECK(etl::binary_search(begin(data), end(data), T(1)));
        CHECK(etl::binary_search(begin(data), end(data), T(2)));
        CHECK_FALSE(etl::binary_search(begin(data), end(data), T(3)));
        CHECK_FALSE(etl::binary_search(begin(data), end(data), T(4)));
    }
}

TEMPLATE_TEST_CASE("algorithm: lower_bound", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;
    using etl::lower_bound;
    auto greater = etl::greater<>();

    SECTION("empty range")
    {
        auto const vec = etl::static_vector<T, 4> {};
        CHECK(lower_bound(begin(vec), end(vec), T(0)) == end(vec));
        CHECK(lower_bound(begin(vec), end(vec), T(0), greater) == end(vec));
    }

    SECTION("single element")
    {
        auto vec = etl::static_vector<T, 4> {};
        vec.push_back(T(0));
        CHECK(lower_bound(begin(vec), end(vec), T(0)) == begin(vec));
        CHECK(lower_bound(begin(vec), end(vec), T(1)) == end(vec));
        CHECK(lower_bound(begin(vec), end(vec), T(0), greater) == begin(vec));
        CHECK(lower_bound(begin(vec), end(vec), T(1), greater) == begin(vec));

        // reset
        vec.clear();
        vec.push_back(T(1));
        CHECK(lower_bound(begin(vec), end(vec), T(0)) == begin(vec));
        CHECK(lower_bound(begin(vec), end(vec), T(1)) == begin(vec));
        CHECK(lower_bound(begin(vec), end(vec), T(0), greater) == end(vec));
        CHECK(lower_bound(begin(vec), end(vec), T(1), greater) == begin(vec));
    }

    SECTION("multiple elements")
    {
        auto const array = etl::array { T(0), T(1), T(2), T(3) };
        CHECK(lower_bound(begin(array), end(array), T(0)) == begin(array));
        CHECK(lower_bound(begin(array), end(array), T(1)) == begin(array) + 1);
        CHECK(lower_bound(begin(array), end(array), T(4)) == end(array));
        CHECK(
            lower_bound(begin(array), end(array), T(0), greater) == end(array));
    }
}

TEMPLATE_TEST_CASE("algorithm: upper_bound", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;
    using etl::upper_bound;
    auto greater = etl::greater<>();

    SECTION("empty range")
    {
        auto const vec = etl::static_vector<T, 4> {};
        CHECK(upper_bound(begin(vec), end(vec), T(0)) == end(vec));
        CHECK(upper_bound(begin(vec), end(vec), T(0), greater) == end(vec));
    }

    SECTION("single element")
    {
        auto vec = etl::static_vector<T, 4> {};
        vec.push_back(T(0));
        CHECK(upper_bound(begin(vec), end(vec), T(0)) == end(vec));
        CHECK(upper_bound(begin(vec), end(vec), T(1)) == end(vec));
        CHECK(upper_bound(begin(vec), end(vec), T(1), greater) == begin(vec));
    }

    SECTION("multiple elements")
    {
        auto const array = etl::array { T(0), T(1), T(2), T(3) };
        CHECK(upper_bound(begin(array), end(array), T(0)) == begin(array) + 1);
        CHECK(upper_bound(begin(array), end(array), T(1)) == begin(array) + 2);
        CHECK(upper_bound(begin(array), end(array), T(5)) == end(array));
    }
}

TEMPLATE_TEST_CASE("algorithm: merge", "[algorithm]", etl::uint8_t, etl::int8_t,
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t, float, double, long double)
{
    using T = TestType;

    SECTION("no overlap")
    {
        auto a = etl::array { T(0), T(0), T(0) };
        auto b = etl::array { T(1), T(1), T(1) };
        CHECK(etl::is_sorted(begin(a), end(a)));
        CHECK(etl::is_sorted(begin(b), end(b)));

        auto merged = etl::static_vector<T, a.size() + b.size()> {};
        etl::merge(
            begin(a), end(a), begin(b), end(b), etl::back_inserter(merged));
        CHECK(merged.size() == 6);
        CHECK(etl::is_sorted(begin(merged), end(merged)));
    }

    SECTION("with overlap")
    {
        auto a = etl::array { T(0), T(1), T(2) };
        auto b = etl::array { T(1), T(2), T(3) };
        CHECK(etl::is_sorted(begin(a), end(a)));
        CHECK(etl::is_sorted(begin(b), end(b)));

        auto merged = etl::static_vector<T, a.size() + b.size()> {};
        etl::merge(
            begin(a), end(a), begin(b), end(b), etl::back_inserter(merged));
        CHECK(merged.size() == 6);
        CHECK(etl::is_sorted(begin(merged), end(merged)));
    }
}

TEMPLATE_TEST_CASE("algorithm: includes", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    SECTION("char")
    {
        auto const v1 = etl::array { 'a', 'b', 'c', 'f', 'h', 'x' };
        auto const v2 = etl::array { 'a', 'b', 'c' };
        auto const v3 = etl::array { 'a', 'c' };
        auto const v4 = etl::array { 'a', 'a', 'b' };
        auto const v5 = etl::array { 'g' };
        auto const v6 = etl::array { 'a', 'c', 'g' };
        auto const v7 = etl::array { 'A', 'B', 'C' };

        auto noCase
            = [](char a, char b) { return etl::tolower(a) < etl::tolower(b); };

        CHECK(etl::includes(v1.begin(), v1.end(), v2.begin(), v2.end()));
        CHECK(etl::includes(v1.begin(), v1.end(), v3.begin(), v3.end()));
        CHECK(
            etl::includes(v1.begin(), v1.end(), v7.begin(), v7.end(), noCase));

        CHECK_FALSE(etl::includes(v1.begin(), v1.end(), v4.begin(), v4.end()));
        CHECK_FALSE(etl::includes(v1.begin(), v1.end(), v5.begin(), v5.end()));
        CHECK_FALSE(etl::includes(v1.begin(), v1.end(), v6.begin(), v6.end()));
    }

    SECTION("TestType")
    {
        using T       = TestType;
        auto const v1 = etl::array { T(1), T(2), T(3), T(6), T(8), T(24) };
        auto const v2 = etl::array { T(1), T(2), T(3) };
        auto const v3 = etl::array { T(1), T(3) };
        auto const v4 = etl::array { T(1), T(1), T(2) };
        auto const v5 = etl::array { T(7) };
        auto const v6 = etl::array { T(1), T(3), T(7) };

        CHECK(etl::includes(v1.begin(), v1.end(), v2.begin(), v2.end()));
        CHECK(etl::includes(v1.begin(), v1.end(), v3.begin(), v3.end()));

        CHECK_FALSE(etl::includes(v1.begin(), v1.end(), v4.begin(), v4.end()));
        CHECK_FALSE(etl::includes(v1.begin(), v1.end(), v5.begin(), v5.end()));
        CHECK_FALSE(etl::includes(v1.begin(), v1.end(), v6.begin(), v6.end()));
    }
}

TEMPLATE_TEST_CASE("algorithm: set_difference", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;

    using etl::back_inserter;
    using etl::begin;
    using etl::end;
    using etl::set_difference;

    SECTION("cppreference.com example #1")
    {
        auto const v1 = etl::array { T(1), T(2), T(5), T(5), T(5), T(9) };
        auto const v2 = etl::array { T(2), T(5), T(7) };
        auto diff     = etl::static_vector<T, 4> {};

        set_difference(
            begin(v1), end(v1), begin(v2), end(v2), back_inserter(diff));

        CHECK(diff[0] == T { 1 });
        CHECK(diff[1] == T { 5 });
        CHECK(diff[2] == T { 5 });
        CHECK(diff[3] == T { 9 });
    }

    SECTION("cppreference.com example #2")
    {
        // we want to know which orders "cut" between old and new states:
        etl::array<T, 4> oldOrders { T(1), T(2), T(5), T(9) };
        etl::array<T, 3> newOrders { T(2), T(5), T(7) };
        etl::static_vector<T, 2> cutOrders {};

        set_difference(oldOrders.begin(), oldOrders.end(), newOrders.begin(),
            newOrders.end(), back_inserter(cutOrders), etl::less<> {});

        CHECK(oldOrders[0] == T { 1 });
        CHECK(oldOrders[1] == T { 2 });
        CHECK(oldOrders[2] == T { 5 });
        CHECK(oldOrders[3] == T { 9 });

        CHECK(newOrders[0] == T { 2 });
        CHECK(newOrders[1] == T { 5 });
        CHECK(newOrders[2] == T { 7 });

        CHECK(cutOrders[0] == T { 1 });
        CHECK(cutOrders[1] == T { 9 });
    }
}

TEMPLATE_TEST_CASE("algorithm: set_intersection", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;

    SECTION("cppreference.com example")
    {
        etl::array<T, 8> v1 { T(1), T(2), T(3), T(4), T(5), T(6), T(7), T(8) };
        etl::array<T, 4> v2 { T(5), T(7), T(9), T(10) };
        etl::sort(v1.begin(), v1.end());
        etl::sort(v2.begin(), v2.end());

        etl::static_vector<T, 2> intersection {};
        etl::set_intersection(v1.begin(), v1.end(), v2.begin(), v2.end(),
            etl::back_inserter(intersection));

        CHECK(intersection[0] == T { 5 });
        CHECK(intersection[1] == T { 7 });
    }
}

TEMPLATE_TEST_CASE("algorithm: set_symmetric_difference", "[algorithm]",
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;

    SECTION("cppreference.com example")
    {
        etl::array<T, 8> v1 { T(1), T(2), T(3), T(4), T(5), T(6), T(7), T(8) };
        etl::array<T, 4> v2 { T(5), T(7), T(9), T(10) };
        etl::sort(v1.begin(), v1.end());
        etl::sort(v2.begin(), v2.end());

        etl::static_vector<T, 8> symDifference {};
        etl::set_symmetric_difference(v1.begin(), v1.end(), v2.begin(),
            v2.end(), etl::back_inserter(symDifference));

        CHECK(symDifference[0] == T { 1 });
        CHECK(symDifference[1] == T { 2 });
        CHECK(symDifference[2] == T { 3 });
        CHECK(symDifference[3] == T { 4 });
        CHECK(symDifference[4] == T { 6 });
        CHECK(symDifference[5] == T { 8 });
        CHECK(symDifference[6] == T { 9 });
        CHECK(symDifference[7] == T { 10 });
    }
}

TEMPLATE_TEST_CASE("algorithm: set_union", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;
    using etl::back_inserter;

    SECTION("cppreference.com example #1")
    {
        etl::array<T, 5> v1 = { T(1), T(2), T(3), T(4), T(5) };
        etl::array<T, 5> v2 = { T(3), T(4), T(5), T(6), T(7) };
        etl::static_vector<T, 7> dest;

        etl::set_union(
            begin(v1), end(v1), begin(v2), end(v2), back_inserter(dest));

        CHECK(dest[0] == T { 1 });
        CHECK(dest[1] == T { 2 });
        CHECK(dest[2] == T { 3 });
        CHECK(dest[3] == T { 4 });
        CHECK(dest[4] == T { 5 });
        CHECK(dest[5] == T { 6 });
        CHECK(dest[6] == T { 7 });
    }

    SECTION("cppreference.com example #1")
    {
        etl::array<T, 7> v1 = { T(1), T(2), T(3), T(4), T(5), T(5), T(5) };
        etl::array<T, 5> v2 = { T(3), T(4), T(5), T(6), T(7) };
        etl::static_vector<T, 9> dest;

        etl::set_union(
            begin(v1), end(v1), begin(v2), end(v2), back_inserter(dest));

        CHECK(dest[0] == T { 1 });
        CHECK(dest[1] == T { 2 });
        CHECK(dest[2] == T { 3 });
        CHECK(dest[3] == T { 4 });
        CHECK(dest[4] == T { 5 });
        CHECK(dest[5] == T { 5 });
        CHECK(dest[6] == T { 5 });
        CHECK(dest[7] == T { 6 });
        CHECK(dest[8] == T { 7 });
    }
}

TEMPLATE_TEST_CASE("algorithm: is_permutation", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;

    SECTION("same data")
    {
        auto const a = etl::array { T(1), T(2), T(3) };
        auto const b = etl::array { T(1), T(2), T(3) };
        CHECK(etl::is_permutation(begin(a), end(a), begin(b), end(b)));
    }

    SECTION("reverse data")
    {
        auto const a = etl::array { T(1), T(2), T(3) };
        auto const b = etl::array { T(3), T(2), T(1) };
        CHECK(etl::is_permutation(begin(a), end(a), begin(b), end(b)));
    }

    SECTION("cppreference.com example")
    {
        auto const a = { T(1), T(2), T(3), T(4), T(5) };
        auto const b = { T(3), T(5), T(4), T(1), T(2) };
        auto const c = { T(3), T(5), T(4), T(1), T(1) };
        CHECK(etl::is_permutation(begin(a), end(a), begin(b), end(b)));
        CHECK_FALSE(etl::is_permutation(begin(a), end(a), begin(c), end(c)));
    }
}

TEMPLATE_TEST_CASE("algorithm: shift_left", "[algorithm]", etl::uint8_t,
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t)
{
    using T = TestType;
    using etl::array;

    auto data = array { T { 1 }, T { 2 }, T { 3 }, T { 4 }, T { 5 }, T { 6 } };
    etl::shift_left(begin(data), end(data), 2);
    REQUIRE(data[0] == T { 3 });
    REQUIRE(data[1] == T { 4 });
    REQUIRE(data[2] == T { 5 });
    REQUIRE(data[3] == T { 6 });
}