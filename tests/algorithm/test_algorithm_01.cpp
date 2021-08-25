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

TEMPLATE_TEST_CASE("algorithm: iter_swap", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    auto data = etl::array { TestType(1), TestType(2) };
    etl::iter_swap(begin(data), begin(data) + 1);
    CHECK(data[0] == TestType(2));
    CHECK(data[1] == TestType(1));
}

TEMPLATE_TEST_CASE("algorithm: swap_ranges", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T       = TestType;
    auto a        = etl::array { T(1), T(2) };
    decltype(a) b = {};

    etl::swap_ranges(begin(a), end(a), begin(b));
    CHECK(a[0] == T(0));
    CHECK(a[1] == T(0));
    CHECK(b[0] == T(1));
    CHECK(b[1] == T(2));
}

TEMPLATE_TEST_CASE("algorithm: for_each", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    etl::static_vector<TestType, 16> vec;
    vec.push_back(TestType(1));
    vec.push_back(TestType(2));
    vec.push_back(TestType(3));
    vec.push_back(TestType(4));

    // Check how often for_each calls the unary function
    int counter {};
    auto incrementCounter = [&counter](auto& /*unused*/) { counter += 1; };

    // for_each
    etl::for_each(vec.begin(), vec.end(), incrementCounter);
    REQUIRE(counter == 4);

    // for_each_n
    counter = 0;
    etl::for_each_n(vec.begin(), 2, incrementCounter);
    REQUIRE(counter == 2);
}

TEMPLATE_TEST_CASE("algorithm: transform", "[algorithm]", etl::uint8_t,
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t, float, double, long double)
{
    etl::array<TestType, 4> a {};
    a.fill(2);
    etl::transform(begin(a), end(a), begin(a),
        [](auto const& val) { return static_cast<TestType>(val * 2); });
    REQUIRE(etl::all_of(
        begin(a), end(a), [](auto const& val) { return val == 4; }));

    etl::static_string<32> str("hello");
    etl::static_vector<TestType, 8> vec;
    etl::transform(begin(str), end(str), etl::back_inserter(vec),
        [](auto c) -> TestType { return static_cast<TestType>(c); });

    REQUIRE(vec[0] == static_cast<TestType>('h'));
    REQUIRE(vec[1] == static_cast<TestType>('e'));
    REQUIRE(vec[2] == static_cast<TestType>('l'));
    REQUIRE(vec[3] == static_cast<TestType>('l'));
    REQUIRE(vec[4] == static_cast<TestType>('o'));

    etl::transform(cbegin(vec), cend(vec), cbegin(vec), begin(vec),
        etl::plus<TestType> {});

    REQUIRE(vec[0] == static_cast<TestType>('h') * 2);
    REQUIRE(vec[1] == static_cast<TestType>('e') * 2);
    REQUIRE(vec[2] == static_cast<TestType>('l') * 2);
    REQUIRE(vec[3] == static_cast<TestType>('l') * 2);
    REQUIRE(vec[4] == static_cast<TestType>('o') * 2);
}

TEMPLATE_TEST_CASE("algorithm: remove", "[algorithm]", etl::uint8_t,
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t)
{
    SECTION("empty range")
    {
        auto data = etl::static_vector<TestType, 4> {};
        auto* res = etl::remove(begin(data), end(data), TestType { 1 });
        CHECK(res == end(data));
        CHECK(data.empty());
    }

    SECTION("found")
    {
        auto data = etl::static_vector<TestType, 4> {};
        data.push_back(TestType { 1 });
        data.push_back(TestType { 0 });
        data.push_back(TestType { 0 });
        data.push_back(TestType { 0 });

        auto* res = etl::remove(begin(data), end(data), TestType { 1 });
        CHECK(res == end(data) - 1);
        CHECK(data[0] == 0);
    }
}

TEMPLATE_TEST_CASE("algorithm: remove_copy/remove_copy_if", "[algorithm]",
    etl::uint8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t)
{
    using T = TestType;

    SECTION("empty range")
    {
        auto source = etl::static_vector<TestType, 4> {};
        auto dest   = etl::static_vector<TestType, 4> {};
        etl::remove_copy(
            begin(source), end(source), etl::back_inserter(dest), T(1));

        CHECK(dest.empty());
    }

    SECTION("range")
    {
        auto source = etl::array { T(1), T(2), T(3), T(4) };
        auto dest   = etl::static_vector<TestType, 4> {};
        etl::remove_copy(
            begin(source), end(source), etl::back_inserter(dest), T(1));

        CHECK_FALSE(dest.empty());
        CHECK(dest.size() == 3);
        CHECK(etl::all_of(
            begin(dest), end(dest), [](auto val) { return val > T(1); }));
    }
}

TEMPLATE_TEST_CASE("algorithm: replace/replace_if", "[algorithm]", etl::uint8_t,
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t)
{
    using T = TestType;

    SECTION("empty range")
    {
        auto data = etl::static_vector<TestType, 4> {};
        etl::replace(begin(data), end(data), T(0), T(1));
        CHECK(data.empty());
    }

    SECTION("range")
    {
        auto data = etl::array { T(1), T(2), T(2), T(3) };
        etl::replace(begin(data), end(data), T(2), T(1));
        CHECK(etl::count(begin(data), end(data), T(2)) == 0);
        CHECK(etl::count(begin(data), end(data), T(1)) == 3);
    }
}

TEMPLATE_TEST_CASE("algorithm: generate", "[algorithm]", etl::uint8_t,
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t)
{
    auto data = etl::array<TestType, 4> {};
    etl::generate(
        begin(data), end(data), [n = TestType { 0 }]() mutable { return n++; });
    REQUIRE(data[0] == 0);
    REQUIRE(data[1] == 1);
    REQUIRE(data[2] == 2);
    REQUIRE(data[3] == 3);
}

TEMPLATE_TEST_CASE("algorithm: generate_n", "[algorithm]", etl::uint8_t,
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t)
{
    auto data = etl::static_vector<TestType, 4> {};
    auto rng  = []() { return TestType { 42 }; };
    etl::generate_n(etl::back_inserter(data), 4, rng);

    REQUIRE(data[0] == TestType { 42 });
    REQUIRE(data[1] == TestType { 42 });
    REQUIRE(data[2] == TestType { 42 });
    REQUIRE(data[3] == TestType { 42 });
}

TEMPLATE_TEST_CASE("algorithm: count", "[algorithm]", etl::uint8_t, etl::int8_t,
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t, float, double)
{
    auto data = etl::array<TestType, 4> {};
    etl::iota(begin(data), end(data), TestType { 0 });
    REQUIRE(etl::count(begin(data), end(data), TestType { 0 }) == 1);
    REQUIRE(etl::count(begin(data), end(data), TestType { 1 }) == 1);
    REQUIRE(etl::count(begin(data), end(data), TestType { 2 }) == 1);
    REQUIRE(etl::count(begin(data), end(data), TestType { 3 }) == 1);
    REQUIRE(etl::count(begin(data), end(data), TestType { 4 }) == 0);
}

TEMPLATE_TEST_CASE("algorithm: count_if", "[algorithm]", etl::uint8_t,
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t, float, double)
{
    auto data = etl::array<TestType, 4> {};
    etl::iota(begin(data), end(data), TestType { 0 });

    auto p1 = [](auto const& val) { return val < TestType { 2 }; };
    auto p2 = [](auto const& val) -> bool { return static_cast<int>(val) % 2; };

    REQUIRE(etl::count_if(begin(data), end(data), p1) == 2);
    REQUIRE(etl::count_if(begin(data), end(data), p2) == 2);
}

TEMPLATE_TEST_CASE("algorithm: mismatch", "[algorithm]", etl::uint8_t,
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t, float, double)
{
    using T = TestType;
    SECTION("first1,last1,first2")
    {
        auto lhs    = etl::array { T(0), T(1), T(2) };
        auto rhs    = etl::array { T(0), T(1), T(3) };
        auto result = etl::mismatch(begin(lhs), end(lhs), begin(rhs));
        CHECK(*result.first == T(2));
        CHECK(*result.second == T(3));
    }

    SECTION("first1,last1,first2,last2")
    {
        auto lhs    = etl::array { T(0), T(1), T(2) };
        auto rhs    = etl::array { T(0), T(1), T(4) };
        auto result = etl::mismatch(begin(lhs), end(lhs), begin(rhs), end(rhs));
        CHECK(*result.first == T(2));
        CHECK(*result.second == T(4));
    }
}

TEMPLATE_TEST_CASE("algorithm: find", "[algorithm]", etl::uint8_t, etl::int8_t,
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t, float, double, long double)
{
    etl::static_vector<TestType, 16> vec;
    vec.push_back(TestType(1));
    vec.push_back(TestType(2));
    vec.push_back(TestType(3));
    vec.push_back(TestType(4));

    const auto* result1 = etl::find(vec.cbegin(), vec.cend(), TestType(3));
    REQUIRE_FALSE(result1 == vec.cend());

    auto* result2 = etl::find(vec.begin(), vec.end(), TestType(5));
    REQUIRE(result2 == vec.end());
}

TEMPLATE_TEST_CASE("algorithm: adjacent_find", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t)
{
    SECTION("empty range")
    {
        auto data = etl::static_vector<TestType, 2> {};
        auto* res = etl::adjacent_find(begin(data), end(data));
        CHECK(res == end(data));
    }

    SECTION("no match")
    {
        auto const data = etl::array { TestType(0), TestType(1), TestType(2) };
        auto const* res = etl::adjacent_find(begin(data), end(data));
        CHECK(res == end(data));
    }

    SECTION("match")
    {
        auto const d1 = etl::array { TestType(0), TestType(0), TestType(2) };
        CHECK(etl::adjacent_find(begin(d1), end(d1)) == begin(d1));

        auto const d2 = etl::array { TestType(0), TestType(2), TestType(2) };
        CHECK(etl::adjacent_find(begin(d2), end(d2)) == begin(d2) + 1);
    }
}

TEMPLATE_TEST_CASE("algorithm: find_if", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t)
{
    etl::static_vector<TestType, 16> vec;
    vec.push_back(TestType(1));
    vec.push_back(TestType(2));
    vec.push_back(TestType(3));
    vec.push_back(TestType(4));

    // find_if
    auto* result3 = etl::find_if(vec.begin(), vec.end(),
        [](auto& x) -> bool { return static_cast<bool>(x % 2); });
    REQUIRE_FALSE(result3 == vec.end());

    auto* result4 = etl::find_if(vec.begin(), vec.end(),
        [](auto& x) -> bool { return static_cast<bool>(x == 100); });
    REQUIRE(result4 == vec.end());
}

TEMPLATE_TEST_CASE("algorithm: find_if_not", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t)
{
    etl::static_vector<TestType, 16> vec;
    vec.push_back(TestType(1));
    vec.push_back(TestType(2));
    vec.push_back(TestType(3));
    vec.push_back(TestType(4));
    // find_if_not
    auto* result5 = etl::find_if_not(vec.begin(), vec.end(),
        [](auto& x) -> bool { return static_cast<bool>(x % 2); });
    REQUIRE_FALSE(result5 == vec.end());

    auto* result6 = etl::find_if_not(vec.begin(), vec.end(),
        [](auto& x) -> bool { return static_cast<bool>(x == 100); });
    REQUIRE_FALSE(result6 == vec.end());

    auto* result7 = etl::find_if_not(vec.begin(), vec.end(),
        [](auto& x) -> bool { return static_cast<bool>(x != 100); });
    REQUIRE(result7 == vec.end());
}

TEMPLATE_TEST_CASE("algorithm: find_first_of", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t)
{
    SECTION("empty range")
    {
        auto tc    = etl::static_vector<TestType, 16> {};
        auto match = etl::array { TestType(2), TestType(42) };
        auto* res
            = etl::find_first_of(begin(tc), end(tc), begin(match), end(match));
        CHECK(res == end(tc));
    }

    SECTION("empty matches")
    {
        auto tc    = etl::static_vector<TestType, 16> {};
        auto match = etl::static_vector<TestType, 16> {};
        auto* res
            = etl::find_first_of(begin(tc), end(tc), begin(match), end(match));
        CHECK(res == end(tc));
    }

    SECTION("no matches")
    {
        auto tc    = etl::array { TestType(0), TestType(1) };
        auto match = etl::array { TestType(2), TestType(42) };
        auto* res
            = etl::find_first_of(begin(tc), end(tc), begin(match), end(match));
        CHECK(res == end(tc));
    }

    SECTION("same ranges")
    {
        auto tc   = etl::array { TestType(0), TestType(1) };
        auto* res = etl::find_first_of(begin(tc), end(tc), begin(tc), end(tc));
        CHECK(res == begin(tc));
    }

    SECTION("matches")
    {
        auto tc    = etl::array { TestType(0), TestType(1), TestType(42) };
        auto match = etl::array { TestType(2), TestType(42) };
        auto* res
            = etl::find_first_of(begin(tc), end(tc), begin(match), end(match));
        CHECK(res == end(tc) - 1);
        CHECK(*res == TestType(42));
    }
}

TEMPLATE_TEST_CASE("algorithm: max", "[algorithm]", etl::int8_t, etl::int16_t,
    etl::int32_t, etl::int64_t, float, double, long double)
{
    REQUIRE(etl::max<TestType>(1, 5) == 5);
    REQUIRE(etl::max<TestType>(-10, 5) == 5);
    REQUIRE(etl::max<TestType>(-10, -20) == -10);

    auto cmp = [](auto x, auto y) { return etl::abs(x) < etl::abs(y) ? y : x; };
    REQUIRE(etl::max<TestType>(-10, -20, cmp) == -20);
    REQUIRE(etl::max<TestType>(10, -20, cmp) == -20);
}

TEMPLATE_TEST_CASE("algorithm: max_element", "[algorithm]", etl::int8_t,
    etl::int16_t, etl::int32_t, etl::int64_t, float, double, long double)
{
    etl::static_vector<TestType, 16> vec;
    vec.push_back(TestType(1));
    vec.push_back(TestType(2));
    vec.push_back(TestType(3));
    vec.push_back(TestType(4));
    vec.push_back(TestType(-5));

    auto const cmp
        = [](auto a, auto b) -> bool { return etl::abs(a) < etl::abs(b); };
    REQUIRE(*etl::max_element(vec.begin(), vec.end()) == TestType(4));
    REQUIRE(*etl::max_element(vec.begin(), vec.end(), cmp) == TestType(-5));
}

TEMPLATE_TEST_CASE("algorithm: min", "[algorithm]", etl::int8_t, etl::int16_t,
    etl::int32_t, etl::int64_t, float, double, long double)
{
    REQUIRE(etl::min<TestType>(1, 5) == 1);
    REQUIRE(etl::min<TestType>(-10, 5) == -10);
    REQUIRE(etl::min<TestType>(-10, -20) == -20);

    auto cmp = [](auto x, auto y) { return etl::abs(x) < etl::abs(y); };
    REQUIRE(etl::min<TestType>(-10, -20, cmp) == -10);
    REQUIRE(etl::min<TestType>(10, -20, cmp) == 10);
}

TEMPLATE_TEST_CASE("algorithm: min_element", "[algorithm]", etl::int8_t,
    etl::int16_t, etl::int32_t, etl::int64_t, float, double, long double)
{
    etl::static_vector<TestType, 16> vec;
    vec.push_back(TestType { 1 });
    vec.push_back(TestType { 2 });
    vec.push_back(TestType { 3 });
    vec.push_back(TestType { 4 });
    vec.push_back(TestType { -5 });

    auto const cmp
        = [](auto a, auto b) -> bool { return etl::abs(a) < etl::abs(b); };
    REQUIRE(*etl::min_element(vec.begin(), vec.end()) == TestType { -5 });
    REQUIRE(*etl::min_element(vec.begin(), vec.end(), cmp) == TestType { 1 });
}

TEMPLATE_TEST_CASE("algorithm: minmax", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    SECTION("in order")
    {
        auto a   = TestType(1);
        auto b   = TestType(2);
        auto res = etl::minmax(a, b);
        CHECK(res.first == a);
        CHECK(res.second == b);
    }

    SECTION("reversed")
    {
        auto a   = TestType(2);
        auto b   = TestType(1);
        auto res = etl::minmax(a, b);
        CHECK(res.first == b);
        CHECK(res.second == a);
    }

    SECTION("same")
    {
        auto a   = TestType(42);
        auto b   = TestType(42);
        auto res = etl::minmax(a, b);
        CHECK(res.first == TestType(42));
        CHECK(res.second == TestType(42));
    }
}
TEMPLATE_TEST_CASE("algorithm: minmax_element", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;

    auto test0 = etl::array { T(1), T(2), T(3) };
    auto res0  = etl::minmax_element(begin(test0), end(test0));
    CHECK(*res0.first == T(1));
    CHECK(*res0.second == T(3));

    auto test1 = etl::array { T(1), T(2), T(3), T(4), T(5), T(6) };
    auto res1  = etl::minmax_element(begin(test1), end(test1));
    CHECK(*res1.first == T(1));
    CHECK(*res1.second == T(6));

    auto test2 = etl::array { T(1), T(4), T(5), T(3), T(2) };
    auto res2  = etl::minmax_element(begin(test2), end(test2));
    CHECK(*res2.first == T(1));
    CHECK(*res2.second == T(5));

    auto test3 = etl::array { T(100), T(99), T(0) };
    auto res3  = etl::minmax_element(begin(test3), end(test3));
    CHECK(*res3.first == T(0));
    CHECK(*res3.second == T(100));
}

TEMPLATE_TEST_CASE("algorithm: clamp", "[algorithm]", etl::uint8_t, etl::int8_t,
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t, float, double, long double)
{
    REQUIRE(etl::clamp<TestType>(55, 0, 20) == TestType { 20 });
    REQUIRE(etl::clamp<TestType>(55, 0, 100) == TestType { 55 });
    STATIC_REQUIRE(etl::clamp<TestType>(55, 0, 20) == TestType { 20 });
    STATIC_REQUIRE(etl::clamp<TestType>(55, 0, 100) == TestType { 55 });
}

TEMPLATE_TEST_CASE("algorithm: all_of", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    etl::static_vector<TestType, 16> vec;
    vec.push_back(1);
    vec.push_back(2);
    vec.push_back(3);
    vec.push_back(4);

    auto const p1 = [](auto a) { return etl::abs(a) > 0; };
    REQUIRE(etl::all_of(vec.begin(), vec.end(), p1));

    auto const p2 = [](auto a) { return etl::abs(a) > 10; };
    REQUIRE_FALSE(etl::all_of(vec.begin(), vec.end(), p2));
}

TEMPLATE_TEST_CASE("algorithm: any_of", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    etl::static_vector<TestType, 16> vec;
    vec.push_back(1);
    vec.push_back(2);
    vec.push_back(3);
    vec.push_back(4);

    auto const p1 = [](auto a) { return etl::abs(a) > 0; };
    REQUIRE(etl::any_of(vec.begin(), vec.end(), p1));
    auto const p2 = [](auto a) { return etl::abs(a) > 10; };
    REQUIRE_FALSE(etl::any_of(vec.begin(), vec.end(), p2));
}

TEMPLATE_TEST_CASE("algorithm: none_of", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    etl::static_vector<TestType, 16> vec;
    vec.push_back(1);
    vec.push_back(2);
    vec.push_back(3);
    vec.push_back(4);

    auto const p1 = [](auto a) { return etl::abs(a) > 10; };
    REQUIRE(etl::none_of(vec.begin(), vec.end(), p1));

    auto const p2 = [](auto a) { return a < 10; };
    REQUIRE_FALSE(etl::none_of(vec.begin(), vec.end(), p2));
}

TEMPLATE_TEST_CASE("algorithm: rotate", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;

    auto data = etl::array { T(1), T(2), T(3), T(4) };
    CHECK(data[0] == 1);

    etl::rotate(begin(data), begin(data) + 1, end(data));
    CHECK(data[0] == 2);
}

TEMPLATE_TEST_CASE("algorithm: rotate_copy", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;

    SECTION("empty range")
    {
        etl::static_vector<T, 5> src {};
        etl::static_vector<T, 5> dest {};
        auto* pivot = etl::find(begin(src), end(src), T(3));

        etl::rotate_copy(
            src.begin(), pivot, src.end(), etl::back_inserter(dest));
        CHECK(dest.empty());
        CHECK(dest.size() == src.size());
    }

    SECTION("cppreference example")
    {
        auto src    = etl::array { T(1), T(2), T(3), T(4), T(5) };
        auto* pivot = etl::find(begin(src), end(src), T(3));

        // From 1, 2, 3, 4, 5 to 3, 4, 5, 1, 2
        etl::static_vector<T, 5> dest {};
        etl::rotate_copy(
            src.begin(), pivot, src.end(), etl::back_inserter(dest));
        CHECK(dest.size() == src.size());
        CHECK(dest[0] == T(3));
        CHECK(dest[1] == T(4));
        CHECK(dest[2] == T(5));
        CHECK(dest[3] == T(1));
        CHECK(dest[4] == T(2));
    }
}

TEMPLATE_TEST_CASE("algorithm: reverse", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    SECTION("built-in")
    {
        auto data = etl::array<TestType, 4> {};
        etl::iota(begin(data), end(data), TestType { 0 });
        etl::reverse(begin(data), end(data));

        CHECK(data[0] == 3);
        CHECK(data[1] == 2);
        CHECK(data[2] == 1);
        CHECK(data[3] == 0);
    }

    SECTION("struct")
    {
        struct S {
            TestType data;
        };

        auto arr = etl::array {
            S { TestType(1) },
            S { TestType(2) },
        };

        etl::reverse(begin(arr), end(arr));

        CHECK(arr[0].data == TestType(2));
        CHECK(arr[1].data == TestType(1));
    }
}

TEMPLATE_TEST_CASE("algorithm: reverse_copy", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    SECTION("built-in")
    {
        auto source = etl::array<TestType, 4> {};
        etl::iota(begin(source), end(source), TestType { 0 });

        auto destination = etl::array<TestType, 4> {};
        etl::reverse_copy(begin(source), end(source), begin(destination));

        CHECK(destination[0] == 3);
        CHECK(destination[1] == 2);
        CHECK(destination[2] == 1);
        CHECK(destination[3] == 0);
    }

    SECTION("struct")
    {
        struct S {
            TestType data;
        };

        auto source = etl::array {
            S { TestType(1) },
            S { TestType(2) },
        };

        decltype(source) destination {};
        etl::reverse_copy(begin(source), end(source), begin(destination));

        CHECK(destination[0].data == TestType(2));
        CHECK(destination[1].data == TestType(1));
    }
}

TEMPLATE_TEST_CASE("algorithm: unique", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;

    SECTION("equal_to")
    {
        auto data = etl::array { T(1), T(1), T(1), T(2), T(3) };
        etl::unique(begin(data), end(data));
        CHECK(data[0] == T(1));
        CHECK(data[1] == T(2));
        CHECK(data[2] == T(3));
    }

    SECTION("not_equal_to")
    {
        auto data = etl::array { T(1), T(1), T(1), T(2), T(3) };
        etl::unique(begin(data), end(data), etl::not_equal_to<> {});
        CHECK(data[0] == T(1));
        CHECK(data[1] == T(1));
        CHECK(data[2] == T(1));
    }
}

TEMPLATE_TEST_CASE("algorithm: unique_copy", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;

    SECTION("equal_to")
    {
        auto source = etl::array { T(1), T(1), T(1), T(2), T(3) };
        decltype(source) dest {};

        etl::unique_copy(begin(source), end(source), begin(dest));
        CHECK(dest[0] == T(1));
        CHECK(dest[1] == T(2));
        CHECK(dest[2] == T(3));
    }

    SECTION("not_equal_to")
    {
        auto source = etl::array { T(1), T(1), T(1), T(2), T(3) };
        decltype(source) dest {};

        etl::unique_copy(
            begin(source), end(source), begin(dest), etl::not_equal_to<> {});
        CHECK(dest[0] == T(1));
        CHECK(dest[1] == T(1));
        CHECK(dest[2] == T(1));
    }
}

TEMPLATE_TEST_CASE("algorithm: partition", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T  = TestType;
    auto arr = etl::array { T(11), T(1), T(12), T(13), T(2), T(3), T(4) };

    etl::partition(begin(arr), end(arr), [](auto n) { return n < 10; });
    REQUIRE(arr[0] == 1);
    REQUIRE(arr[1] == 2);
    REQUIRE(arr[2] == 3);
    REQUIRE(arr[3] == 4);
}

TEMPLATE_TEST_CASE("algorithm: partition_copy", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;
    using etl::all_of;

    SECTION("empty range")
    {
        auto src    = etl::static_vector<T, 5> {};
        auto dTrue  = etl::array<T, 5> {};
        auto dFalse = etl::array<T, 5> {};
        auto pred   = [](auto n) { return n < 10; };

        auto res = etl::partition_copy(
            begin(src), end(src), begin(dTrue), begin(dFalse), pred);
        CHECK(res.first == begin(dTrue));
        CHECK(res.second == begin(dFalse));
    }

    SECTION("range")
    {
        auto src   = etl::array { T(11), T(1), T(12), T(13), T(2), T(3), T(4) };
        auto dTrue = etl::static_vector<T, 5> {};
        auto dFalse    = etl::static_vector<T, 5> {};
        auto predicate = [](auto n) { return n < 10; };

        auto falseIt = etl::back_inserter(dFalse);
        auto trueIt  = etl::back_inserter(dTrue);
        etl::partition_copy(begin(src), end(src), trueIt, falseIt, predicate);

        CHECK(dTrue.size() == 4);
        CHECK(all_of(begin(dTrue), end(dTrue), [](auto v) { return v < 10; }));
        CHECK(dFalse.size() == 3);
        CHECK(
            all_of(begin(dFalse), end(dFalse), [](auto v) { return v >= 10; }));
    }
}

TEMPLATE_TEST_CASE("algorithm: partition_point", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;

    SECTION("empty range")
    {
        auto data = etl::static_vector<T, 5> {};
        auto pred = [](auto v) { return v < 10; };
        auto* res = etl::partition_point(begin(data), end(data), pred);
        CHECK(res == end(data));
    }

    SECTION("range")
    {
        auto data = etl::array { T(1), T(2), T(10), T(11) };
        auto pred = [](auto v) { return v < 10; };
        auto* res = etl::partition_point(begin(data), end(data), pred);
        CHECK_FALSE(res == end(data));
        CHECK(*res == T(10));
    }
}

TEMPLATE_TEST_CASE("algorithm: stable_partition", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T  = TestType;
    auto arr = etl::array { T(11), T(1), T(12), T(13), T(2), T(3), T(4) };

    etl::stable_partition(begin(arr), end(arr), [](auto n) { return n < 10; });
    REQUIRE(arr[0] == 1);
    REQUIRE(arr[1] == 2);
    REQUIRE(arr[2] == 3);
    REQUIRE(arr[3] == 4);
    REQUIRE(arr[4] == 11);
    REQUIRE(arr[5] == 12);
    REQUIRE(arr[6] == 13);
}
