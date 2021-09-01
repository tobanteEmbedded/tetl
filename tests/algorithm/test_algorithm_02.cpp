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

TEMPLATE_TEST_CASE("algorithm: search", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;

    SECTION("find match")
    {
        auto source = etl::array { T(0), T(0), T(0), T(1), T(2), T(3) };
        auto target = etl::array { T(1), T(2), T(3) };
        auto* res   = etl::search(
            begin(source), end(source), begin(target), end(target));
        CHECK(*res == T(1));
    }

    SECTION("no match")
    {
        auto source = etl::array { T(0), T(0), T(0), T(0), T(2), T(3) };
        auto target = etl::array { T(1), T(2), T(3) };
        auto* res   = etl::search(
            begin(source), end(source), begin(target), end(target));
        CHECK(res == end(source));
    }

    SECTION("match range empty")
    {
        auto source = etl::array { T(0), T(0), T(0), T(0), T(2), T(3) };
        auto target = etl::static_vector<T, 0> {};
        auto* res   = etl::search(
            begin(source), end(source), begin(target), end(target));
        CHECK(res == begin(source));
    }

    SECTION("searcher")
    {
        auto source = etl::array { T(0), T(0), T(0), T(1), T(2), T(3) };

        auto t1 = etl::array { T(1), T(2), T(3) };
        auto s1 = etl::default_searcher(t1.begin(), t1.end());
        CHECK(*etl::search(source.begin(), source.end(), s1) == T(1));

        auto t2 = etl::static_vector<T, 0> {};
        auto s2 = etl::default_searcher(t2.begin(), t2.end());
        CHECK(etl::search(source.begin(), source.end(), s2) == begin(source));
    }
}

TEMPLATE_TEST_CASE("algorithm: search_n", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;

    SECTION("empty range")
    {
        auto source = etl::static_vector<T, 2> {};
        auto* res   = etl::search_n(begin(source), end(source), 3, T(0));
        CHECK(res == end(source));
    }

    SECTION("zero or negative count")
    {
        auto source = etl::array { T(0), T(0), T(0), T(1), T(2), T(3) };
        CHECK(etl::search_n(begin(source), end(source), 0, T(0))
              == begin(source));

        if constexpr (etl::numeric_limits<T>::is_signed) {
            CHECK(etl::search_n(begin(source), end(source), -1, T(0))
                  == begin(source));
            CHECK(etl::search_n(begin(source), end(source), -2, T(0))
                  == begin(source));
        }
    }

    SECTION("no match")
    {
        auto source = etl::array { T(0), T(0), T(0), T(1), T(2), T(3) };
        auto* res   = etl::search_n(begin(source), end(source), 3, T(42));
        CHECK(res == end(source));
    }

    SECTION("find match")
    {
        auto source = etl::array { T(0), T(0), T(0), T(1), T(2), T(3) };
        auto* res   = etl::search_n(begin(source), end(source), 3, T(0));
        CHECK(res == begin(source));
        CHECK(*res == T(0));
    }
}

TEMPLATE_TEST_CASE("algorithm: find_end", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;

    SECTION("cppreference.com example")
    {
        etl::array<T, 12> v { 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4 };
        etl::array<T, 3> t1 { 1, 2, 3 };

        auto* result = etl::find_end(begin(v), end(v), begin(t1), end(t1));
        CHECK(etl::distance(begin(v), result) == 8);

        etl::array<T, 3> t2 { 4, 5, 6 };
        result = etl::find_end(begin(v), end(v), begin(t2), end(t2));
        CHECK(result == end(v));
    }
}

TEMPLATE_TEST_CASE("algorithm: move", "[algorithm]", etl::uint8_t, etl::int8_t,
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t, float, double, long double)
{
    // test struct
    struct S {
        S(TestType d = TestType(0)) : data { d } { }

        S(S const& s)
        {
            data = s.data;
            copy = true;
        }

        S(S&& s) noexcept
        {
            data = s.data;
            move = true;
        }

        auto operator=(S const& s) noexcept -> S&
        {
            data = s.data;
            copy = true;
            return *this;
        }

        auto operator=(S&& s) noexcept -> S&
        {
            data = s.data;
            move = true;
            return *this;
        }

        TestType data;
        bool copy = false;
        bool move = false;
    };

    SECTION("move forward")
    {
        // move
        using etl::array;
        auto source = array { S { TestType { 1 } }, S { TestType { 1 } },
            S { TestType { 1 } } };
        decltype(source) d {};
        etl::move(begin(source), end(source), begin(d));

        // assert
        using etl::all_of;
        CHECK(all_of(begin(d), end(d), [](auto const& s) { return s.move; }));
        CHECK(all_of(begin(d), end(d), [](auto const& s) { return !s.copy; }));
        CHECK(all_of(
            begin(d), end(d), [](auto const& s) { return s.data == 1; }));
    }

    SECTION("move backward")
    {
        // move
        using etl::array;
        auto source = array { S { TestType { 1 } }, S { TestType { 2 } },
            S { TestType { 3 } } };
        decltype(source) d {};
        etl::move_backward(begin(source), end(source), end(d));

        // assert
        using etl::all_of;
        CHECK(all_of(begin(d), end(d), [](auto const& s) { return s.move; }));
        CHECK(all_of(begin(d), end(d), [](auto const& s) { return !s.copy; }));
        CHECK(all_of(
            begin(d), end(d), [](auto const& s) { return s.data != 0; }));
        CHECK(d[0].data == TestType(1));
        CHECK(d[1].data == TestType(2));
        CHECK(d[2].data == TestType(3));
    }
}

TEMPLATE_TEST_CASE("algorithm: equal", "[algorithm]", etl::uint8_t, etl::int8_t,
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t, float, double, long double)
{
    auto lhs = etl::array<TestType, 2> { TestType { 0 }, TestType { 1 } };
    auto rhs = etl::array<TestType, 2> { TestType { 0 }, TestType { 1 } };
    auto cmp = etl::not_equal_to<> {};

    CHECK(etl::equal(begin(lhs), end(lhs), begin(rhs)));
    CHECK_FALSE(etl::equal(begin(lhs), end(lhs), begin(rhs), cmp));

    CHECK(etl::equal(begin(lhs), end(lhs), begin(rhs), end(rhs)));
    CHECK_FALSE(etl::equal(begin(lhs), end(lhs), begin(rhs), end(rhs), cmp));
}
