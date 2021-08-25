/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/span.hpp"

#include "etl/algorithm.hpp"
#include "etl/iterator.hpp"
#include "etl/vector.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEMPLATE_TEST_CASE("span: deduction guides", "[span]", char, int, float)
{
    SECTION("from C array")
    {
        TestType arr[16] = {};
        auto sp          = etl::span { arr };
        REQUIRE(sp.data() == &arr[0]);
        REQUIRE(sp.size() == 16);
    }

    SECTION("from etl::array")
    {
        auto arr = etl::array<TestType, 8> {};
        auto sp  = etl::span { arr };
        REQUIRE(sp.data() == arr.data());
        REQUIRE(sp.size() == 8);
    }

    SECTION("from etl::array const")
    {
        auto const arr = etl::array<TestType, 8> {};
        auto const sp  = etl::span { arr };
        REQUIRE(sp.data() == arr.data());
        REQUIRE(sp.size() == 8);
    }

    SECTION("from Container")
    {
        auto vec = etl::static_vector<TestType, 8> {};
        vec.push_back(TestType {});
        vec.push_back(TestType {});
        auto sp = etl::span { vec };
        REQUIRE(sp.data() == vec.data());
        REQUIRE(sp.size() == 2);
    }

    SECTION("from Container const")
    {
        auto const vec = []() {
            auto v = etl::static_vector<TestType, 8> {};
            v.push_back(TestType {});
            v.push_back(TestType {});
            return v;
        }();

        auto const sp = etl::span { vec };
        REQUIRE(sp.data() == vec.data());
        REQUIRE(sp.size() == 2);
    }
}

TEST_CASE("span: ctor(default)", "[span]")
{
    auto sp = etl::span<char> {};
    REQUIRE(sp.data() == nullptr);
    REQUIRE(sp.size() == 0);
    REQUIRE(sp.empty());
}

TEMPLATE_TEST_CASE("span: ctor(first,count)", "[span]", char, int, float)
{
    SECTION("static extent")
    {
        auto arr = etl::array<TestType, 8> {};
        auto sp  = etl::span<TestType, 8> { etl::begin(arr), etl::size(arr) };
        REQUIRE_FALSE(sp.empty());
        REQUIRE(sp.data() == arr.data());
        REQUIRE(sp.size() == arr.size());
        REQUIRE(sp.extent == arr.size());
    }

    SECTION("static array")
    {
        auto arr = etl::array<TestType, 8> {};
        auto sp  = etl::span<TestType> { etl::begin(arr), etl::size(arr) };
        REQUIRE_FALSE(sp.empty());
        REQUIRE(sp.data() == arr.data());
        REQUIRE(sp.size() == arr.size());
        REQUIRE(sp.extent == etl::dynamic_extent);
    }

    SECTION("static vector")
    {
        auto vec = etl::static_vector<TestType, 8> {};
        auto rng = []() { return TestType { 42 }; };
        etl::generate_n(etl::back_inserter(vec), 4, rng);

        auto sp = etl::span<TestType> { etl::begin(vec), etl::size(vec) };
        REQUIRE_FALSE(sp.empty());
        REQUIRE(sp.data() == vec.data());
        REQUIRE(sp.size() == vec.size());
        REQUIRE(sp.extent == etl::dynamic_extent);
        REQUIRE(etl::all_of(etl::begin(sp), etl::end(sp),
            [](auto& x) { return x == TestType { 42 }; }));
    }
}

TEMPLATE_TEST_CASE("span: begin/end", "[span]", char, int, float)
{
    SECTION("empty")
    {
        auto sp = etl::span<TestType> {};
        REQUIRE(sp.begin() == sp.end());
        REQUIRE(etl::begin(sp) == etl::end(sp));
        REQUIRE(sp.size() == 0);
    }

    SECTION("ranged-for")
    {
        auto data = etl::array<TestType, 4> {};
        auto sp   = etl::span<TestType> { etl::begin(data), etl::size(data) };
        REQUIRE_FALSE(sp.begin() == sp.end());
        REQUIRE_FALSE(etl::begin(sp) == etl::end(sp));

        auto counter = 0;
        for (auto const& x : sp) {
            etl::ignore_unused(x);
            counter++;
        }
        REQUIRE(counter == 4);
    }

    SECTION("algorithm")
    {
        auto data = etl::array<TestType, 4> {};
        auto sp   = etl::span<TestType> { etl::begin(data), etl::size(data) };
        REQUIRE_FALSE(sp.begin() == sp.end());
        REQUIRE_FALSE(etl::begin(sp) == etl::end(sp));

        auto counter = 0;
        etl::for_each(etl::begin(sp), etl::end(sp),
            [&counter](auto /*unused*/) { counter++; });
        REQUIRE(counter == 4);
    }
}

TEMPLATE_TEST_CASE("span: operator[]", "[span]", char, int, float)
{
    auto rng = []() {
        static auto i = TestType { 127 };
        return TestType { i-- };
    };

    auto vec = etl::static_vector<TestType, 8> {};
    etl::generate_n(etl::back_inserter(vec), 4, rng);
    auto sp = etl::span<TestType> { etl::begin(vec), etl::size(vec) };
    REQUIRE(sp[0] == TestType { 127 });
    REQUIRE(sp[1] == TestType { 126 });
    REQUIRE(sp[2] == TestType { 125 });
    REQUIRE(sp[3] == TestType { 124 });

    auto const csp = etl::span { sp };
    REQUIRE(csp[0] == TestType { 127 });
    REQUIRE(csp[1] == TestType { 126 });
    REQUIRE(csp[2] == TestType { 125 });
    REQUIRE(csp[3] == TestType { 124 });
}

TEMPLATE_TEST_CASE(
    "span: size_bytes", "[span]", char, int, float, double, etl::uint64_t)
{
    auto vec = etl::static_vector<TestType, 6> {};
    etl::generate_n(
        etl::back_inserter(vec), 4, []() { return TestType { 42 }; });
    auto sp = etl::span<TestType> { etl::begin(vec), etl::size(vec) };

    REQUIRE(sp.size_bytes() == 4 * sizeof(TestType));
}

TEMPLATE_TEST_CASE(
    "span: first", "[span]", char, int, float, double, etl::uint64_t)
{
    using T   = TestType;
    auto data = etl::array { T(0), T(1), T(2), T(3), T(4), T(5), T(6) };
    auto sp   = etl::span<T> { data };

    auto one = sp.first(1);
    REQUIRE(one.size() == 1);
    REQUIRE(one[0] == T(0));

    auto two = sp.first(2);
    REQUIRE(two.size() == 2);
    REQUIRE(two[0] == T(0));
    REQUIRE(two[1] == T(1));

    auto onet = sp.template first<1>();
    REQUIRE(onet.size() == 1);
    REQUIRE(onet[0] == T(0));

    auto twot = sp.template first<2>();
    REQUIRE(twot.size() == 2);
    REQUIRE(twot[0] == T(0));
    REQUIRE(twot[1] == T(1));
}

TEMPLATE_TEST_CASE(
    "span: last", "[span]", char, int, float, double, etl::uint64_t)
{
    using T   = TestType;
    auto data = etl::array { T(0), T(1), T(2), T(3), T(4), T(5), T(6) };
    auto sp   = etl::span<T> { data };

    auto one = sp.last(1);
    REQUIRE(one.size() == 1);
    REQUIRE(one[0] == T(6));

    auto two = sp.last(2);
    REQUIRE(two.size() == 2);
    REQUIRE(two[0] == T(5));
    REQUIRE(two[1] == T(6));

    auto onet = sp.template last<1>();
    REQUIRE(onet.size() == 1);
    REQUIRE(onet[0] == T(6));

    auto twot = sp.template last<2>();
    REQUIRE(twot.size() == 2);
    REQUIRE(twot[0] == T(5));
    REQUIRE(twot[1] == T(6));
}

TEMPLATE_TEST_CASE(
    "span: as_bytes", "[span]", char, int, float, double, etl::uint64_t)
{
    using T   = TestType;
    auto data = etl::array<T, 6> {};
    auto sp   = etl::span<T> { data };
    REQUIRE(etl::as_bytes(sp).size() == sizeof(T) * data.size());
    REQUIRE(etl::as_writable_bytes(sp).size() == sizeof(T) * data.size());
}