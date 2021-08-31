/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/numeric.hpp"

#include "etl/array.hpp"    // for array
#include "etl/cstdint.hpp"  // for int16_t, int32_t, int64_t, int8_t
#include "etl/iterator.hpp" // for next, prev
#include "etl/limits.hpp"   // for numeric_limits
#include "etl/vector.hpp"   // for static_vector

#include "catch2/catch_template_test_macros.hpp"

TEMPLATE_TEST_CASE("numeric: abs(integer)", "[numeric]", etl::int8_t,
    etl::int16_t, etl::int32_t, etl::int64_t)
{
    REQUIRE(etl::abs<TestType>(0) == TestType { 0 });
    REQUIRE(etl::abs<TestType>(1) == TestType { 1 });
    REQUIRE(etl::abs<TestType>(-1) == TestType { 1 });
    REQUIRE(etl::abs<TestType>(10) == TestType { 10 });
    REQUIRE(etl::abs<TestType>(-10) == TestType { 10 });
}

TEMPLATE_TEST_CASE(
    "numeric: abs(floating)", "[numeric]", float, double, long double)
{
    REQUIRE(etl::abs<TestType>(0) == TestType { 0 });
    REQUIRE(etl::abs<TestType>(1) == TestType { 1 });
    REQUIRE(etl::abs<TestType>(-1) == TestType { 1 });
    REQUIRE(etl::abs<TestType>(10) == TestType { 10 });
    REQUIRE(etl::abs<TestType>(-10) == TestType { 10 });
}

TEMPLATE_TEST_CASE("numeric: iota", "[numeric]", etl::int16_t, etl::int32_t,
    etl::int64_t, etl::uint16_t, etl::uint32_t, etl::uint64_t, float, double,
    long double)
{
    SECTION("from 0")
    {
        auto data = etl::array<TestType, 4> {};
        etl::iota(begin(data), end(data), TestType { 0 });
        CHECK(data[0] == 0);
        CHECK(data[1] == 1);
        CHECK(data[2] == 2);
        CHECK(data[3] == 3);
    }

    SECTION("from 42")
    {
        auto data = etl::array<TestType, 4> {};
        etl::iota(begin(data), end(data), TestType { 42 });
        CHECK(data[0] == 42);
        CHECK(data[1] == 43);
        CHECK(data[2] == 44);
        CHECK(data[3] == 45);
    }
}

TEMPLATE_TEST_CASE("numeric: adjacent_difference", "[numeric]", etl::int16_t,
    etl::int32_t, etl::int64_t, etl::uint16_t, etl::uint32_t, etl::uint64_t,
    float, double, long double)
{
    using T = TestType;

    using etl::adjacent_difference;
    using etl::array;
    using etl::begin;
    using etl::end;
    using etl::next;
    using etl::plus;
    using etl::prev;

    SECTION("cppreference.com example")
    {
        array a { T(2), T(4), T(6) };
        adjacent_difference(a.begin(), a.end(), a.begin());
        REQUIRE(a[0] == 2);
        REQUIRE(a[1] == 2);
        REQUIRE(a[2] == 2);
    }

    SECTION("cppreference.com example fibonacci")
    {
        array<T, 4> a { T(1) };
        adjacent_difference(begin(a), prev(end(a)), next(begin(a)), plus<T> {});
        REQUIRE(a[0] == 1);
        REQUIRE(a[1] == 1);
        REQUIRE(a[2] == 2);
        REQUIRE(a[3] == 3);
    }
}

TEMPLATE_TEST_CASE("numeric: inner_product", "[numeric]", etl::int16_t,
    etl::int32_t, etl::int64_t, etl::uint16_t, etl::uint32_t, etl::uint64_t,
    float, double, long double)
{
    // 0 1 2 3 4
    etl::static_vector<TestType, 6> a {};
    a.push_back(TestType { 0 });
    a.push_back(TestType { 1 });
    a.push_back(TestType { 2 });
    a.push_back(TestType { 3 });
    a.push_back(TestType { 4 });

    // 5 4 3 2 1
    etl::static_vector<TestType, 6> b {};
    b.push_back(TestType { 5 });
    b.push_back(TestType { 4 });
    b.push_back(TestType { 2 });
    b.push_back(TestType { 3 });
    b.push_back(TestType { 1 });

    auto product
        = etl::inner_product(a.begin(), a.end(), b.begin(), TestType { 0 });
    REQUIRE(product == TestType { 21 });

    auto pairwiseMatches = etl::inner_product(a.begin(), a.end(), b.begin(),
        TestType { 0 }, etl::plus<TestType> {}, etl::equal_to<TestType> {});
    REQUIRE(pairwiseMatches == TestType { 2 });
}

// TEMPLATE_TEST_CASE("numeric: partial_sum", "[numeric]", etl::int16_t,
// etl::int32_t,
//                    etl::int64_t, etl::uint16_t, etl::uint32_t, etl::uint64_t,
//                    float, double, long double)
// {
//     SECTION("plus")
//     {
//         etl::static_vector<TestType, 5> vec {5, TestType {2}};
//         etl::partial_sum(vec.begin(), vec.end(), vec.begin());
//         REQUIRE(vec[0] == TestType {2});
//         REQUIRE(vec[1] == TestType {4});
//         REQUIRE(vec[2] == TestType {6});
//         REQUIRE(vec[3] == TestType {8});
//     }

//     SECTION("multiplies (pow2)")
//     {
//         etl::static_vector<TestType, 5> vec {5, TestType {2}};
//         etl::partial_sum(vec.begin(), vec.end(), vec.begin(),
//         etl::multiplies<>()); REQUIRE(vec[0] == TestType {2}); REQUIRE(vec[1]
//         == TestType {4}); REQUIRE(vec[2] == TestType {8}); REQUIRE(vec[3] ==
//         TestType {16});
//     }
// }

TEMPLATE_TEST_CASE("numeric: accumulate", "[numeric]", etl::int16_t,
    etl::int32_t, etl::int64_t, etl::uint16_t, etl::uint32_t, etl::uint64_t,
    float, double, long double)
{
    using T  = TestType;
    auto vec = etl::array { T(1), T(2), T(3), T(4) };

    REQUIRE(etl::accumulate(vec.begin(), vec.end(), T { 0 }) == T(10));

    auto func = [](T a, T b) { return static_cast<T>(a + (b * T { 2 })); };
    REQUIRE(etl::accumulate(vec.begin(), vec.end(), T { 0 }, func) == T(20));
}

TEMPLATE_TEST_CASE("numeric: reduce", "[numeric]", etl::int32_t, etl::int64_t,
    etl::uint32_t, etl::uint64_t, float, double, long double)
{
    using T  = TestType;
    auto vec = etl::array { T(1), T(2), T(3), T(4) };
    REQUIRE(etl::reduce(vec.begin(), vec.end()) == T(10));
    REQUIRE(etl::reduce(vec.begin(), vec.end(), T { 0 }) == T(10));

    auto func = [](T a, T b) { return static_cast<T>(a + (b * T { 2 })); };
    REQUIRE(etl::reduce(vec.begin(), vec.end(), T { 0 }, func) == T(20));
}

TEMPLATE_TEST_CASE("numeric: gcd", "[numeric]", etl::uint8_t, etl::int8_t,
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t)
{
    REQUIRE(etl::gcd(5, 10) == 5);
    REQUIRE(etl::gcd(10, 5) == 5);
    STATIC_REQUIRE(etl::gcd(10, 5) == 5);

    REQUIRE(etl::gcd(30, 105) == 15);
    REQUIRE(etl::gcd(105, 30) == 15);
    STATIC_REQUIRE(etl::gcd(105, 30) == 15);
}

TEMPLATE_TEST_CASE("numeric: lcm", "[numeric]", etl::uint8_t, etl::int8_t,
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t)
{
    STATIC_REQUIRE(
        etl::lcm(TestType { 10 }, TestType { 5 }) == TestType { 10 });

    REQUIRE(etl::lcm(TestType { 4 }, TestType { 6 }) == TestType { 12 });
    REQUIRE(etl::lcm(TestType { 6 }, TestType { 4 }) == TestType { 12 });
    REQUIRE(etl::lcm(TestType { 30 }, TestType { 120 }) == TestType { 120 });
}
