/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

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
