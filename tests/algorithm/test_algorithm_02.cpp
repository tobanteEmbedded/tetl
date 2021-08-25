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

TEMPLATE_TEST_CASE("algorithm: copy", "[algorithm]", etl::uint8_t, etl::int8_t,
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t, float, double, long double)
{
    using vector_t = etl::static_vector<TestType, 4>;

    auto source = etl::array<TestType, 4> {};
    source[0]   = TestType { 1 };
    source[1]   = TestType { 2 };
    source[2]   = TestType { 3 };
    source[3]   = TestType { 4 };

    SECTION("copy to c array")
    {
        TestType dest[4] = {};
        etl::copy(begin(source), end(source), etl::begin(dest));
        REQUIRE(dest[0] == TestType { 1 });
        REQUIRE(dest[1] == TestType { 2 });
        REQUIRE(dest[2] == TestType { 3 });
        REQUIRE(dest[3] == TestType { 4 });
    }

    SECTION("copy to vector")
    {
        auto dest = vector_t {};
        REQUIRE(dest.size() == 0);
        etl::copy(begin(source), end(source), etl::back_inserter(dest));
        REQUIRE(dest.size() == 4);
        REQUIRE(dest[0] == TestType { 1 });
        REQUIRE(dest[1] == TestType { 2 });
        REQUIRE(dest[2] == TestType { 3 });
        REQUIRE(dest[3] == TestType { 4 });
    }
}

TEMPLATE_TEST_CASE("algorithm: copy_if", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using vector_t = etl::static_vector<TestType, 4>;

    auto source = etl::array<TestType, 4> {};
    source[0]   = TestType { 1 };
    source[1]   = TestType { 7 };
    source[2]   = TestType { 3 };
    source[3]   = TestType { 9 };

    auto predicate = [](auto const& val) { return static_cast<int>(val) >= 5; };

    SECTION("copy_if to c array")
    {
        TestType dest[4] = {};
        auto* res        = etl::copy_if(
            begin(source), end(source), etl::begin(dest), predicate);
        REQUIRE(res == &dest[2]);
        REQUIRE(dest[0] == TestType { 7 });
        REQUIRE(dest[1] == TestType { 9 });
        REQUIRE(dest[2] == TestType { 0 });
        REQUIRE(dest[3] == TestType { 0 });
    }

    SECTION("copy_if to vector")
    {
        auto dest = vector_t {};
        REQUIRE(dest.size() == 0);
        etl::copy_if(
            begin(source), end(source), etl::back_inserter(dest), predicate);
        REQUIRE(dest.size() == 2);
        REQUIRE(dest[0] == TestType { 7 });
        REQUIRE(dest[1] == TestType { 9 });
    }
}

TEMPLATE_TEST_CASE("algorithm: copy_n", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T           = TestType;
    using vector_t    = etl::static_vector<T, 4>;
    auto const source = etl::array<T, 4> { T { 1 }, T { 2 }, T { 3 }, T { 4 } };

    SECTION("copy_n to c array")
    {
        SECTION("all elements")
        {
            T dest[4] = {};
            etl::copy_n(begin(source), 4, etl::begin(dest));
            REQUIRE(dest[0] == T { 1 });
            REQUIRE(dest[1] == T { 2 });
            REQUIRE(dest[2] == T { 3 });
            REQUIRE(dest[3] == T { 4 });
        }

        SECTION("2 elements")
        {
            T dest[3] = {};
            etl::copy_n(begin(source), 2, etl::begin(dest));
            REQUIRE(dest[0] == T { 1 });
            REQUIRE(dest[1] == T { 2 });
            REQUIRE(dest[2] == T { 0 });
        }
    }

    SECTION("copy_n to vector")
    {
        auto dest = vector_t {};
        REQUIRE(dest.size() == 0);
        etl::copy_n(begin(source), source.size(), etl::back_inserter(dest));
        REQUIRE(dest.size() == 4);
        REQUIRE(dest[0] == T { 1 });
        REQUIRE(dest[1] == T { 2 });
        REQUIRE(dest[2] == T { 3 });
        REQUIRE(dest[3] == T { 4 });
    }
}

TEMPLATE_TEST_CASE("algorithm: copy_backward", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    auto source = etl::array<TestType, 4> {};
    source[0]   = TestType { 1 };
    source[1]   = TestType { 2 };
    source[2]   = TestType { 3 };
    source[3]   = TestType { 4 };

    SECTION("copy_backward to c array")
    {
        TestType dest[4] = {};
        etl::copy_backward(begin(source), end(source), etl::end(dest));
        REQUIRE(dest[0] == TestType { 1 });
        REQUIRE(dest[1] == TestType { 2 });
        REQUIRE(dest[2] == TestType { 3 });
        REQUIRE(dest[3] == TestType { 4 });
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

TEMPLATE_TEST_CASE("algorithm: fill", "[algorithm]", etl::uint8_t, etl::int8_t,
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t, float, double, long double)
{
    SECTION("c array")
    {
        TestType source[4] = {};
        etl::fill(etl::begin(source), etl::end(source), TestType { 42 });

        auto const all42 = etl::all_of(etl::begin(source), etl::end(source),
            [](auto const& val) { return val == TestType { 42 }; });

        REQUIRE(all42);
    }

    SECTION("etl::array")
    {
        auto source = etl::array<TestType, 4> {};
        etl::fill(begin(source), end(source), TestType { 42 });

        auto const all42 = etl::all_of(begin(source), end(source),
            [](auto const& val) { return val == TestType { 42 }; });

        REQUIRE(all42);
    }
}

TEMPLATE_TEST_CASE("algorithm: fill_n", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;

    SECTION("c array")
    {
        using etl::begin;
        using etl::end;

        T tc[4] = {};
        etl::fill_n(begin(tc), 4, T { 42 });
        CHECK(
            etl::all_of(begin(tc), end(tc), [](auto v) { return v == T(42); }));
    }

    SECTION("etl::array")
    {
        auto tc0 = etl::array<T, 4> {};
        CHECK(etl::fill_n(begin(tc0), 0, T { 42 }) == begin(tc0));

        auto tc1 = etl::array<T, 4> {};
        CHECK(etl::fill_n(begin(tc1), 4, T { 42 }) == end(tc1));
        CHECK(etl::all_of(
            begin(tc1), end(tc1), [](auto v) { return v == T(42); }));

        auto tc2   = etl::array<T, 4> {};
        auto* res2 = etl::fill_n(begin(tc2), 2, T { 42 });
        CHECK(res2 != begin(tc2));
        CHECK(res2 != end(tc2));
        CHECK(tc2[0] == T(42));
        CHECK(tc2[1] == T(42));
        CHECK(tc2[2] == T(0));
        CHECK(tc2[3] == T(0));
    }
}

TEMPLATE_TEST_CASE("algorithm: sort", "[algorithm]", etl::uint8_t, etl::int8_t,
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t, float, double, long double)
{
    SECTION("already sorted")
    {
        auto source = etl::array<TestType, 4> {};
        source[0]   = TestType { 1 };
        source[1]   = TestType { 2 };
        source[2]   = TestType { 3 };
        source[3]   = TestType { 4 };

        etl::sort(begin(source), end(source), etl::less<TestType> {});
        REQUIRE(source[0] == TestType { 1 });
        REQUIRE(source[1] == TestType { 2 });
        REQUIRE(source[2] == TestType { 3 });
        REQUIRE(source[3] == TestType { 4 });
    }

    SECTION("reversed")
    {
        auto source = etl::array<TestType, 4> {};
        source[0]   = TestType { 4 };
        source[1]   = TestType { 3 };
        source[2]   = TestType { 2 };
        source[3]   = TestType { 1 };

        etl::sort(begin(source), end(source));
        REQUIRE(source[0] == TestType { 1 });
        REQUIRE(source[1] == TestType { 2 });
        REQUIRE(source[2] == TestType { 3 });
        REQUIRE(source[3] == TestType { 4 });
    }

    SECTION("custom compare")
    {
        auto source = etl::array<TestType, 4> {};
        source[0]   = TestType { 1 };
        source[1]   = TestType { 1 };
        source[2]   = TestType { 56 };
        source[3]   = TestType { 42 };

        etl::sort(begin(source), end(source),
            [](auto const& lhs, auto const& rhs) { return lhs > rhs; });
        REQUIRE(source[0] == TestType { 56 });
        REQUIRE(source[1] == TestType { 42 });
        REQUIRE(source[2] == TestType { 1 });
        REQUIRE(source[3] == TestType { 1 });
    }
}

TEMPLATE_TEST_CASE("algorithm: stable_sort", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;

    SECTION("empty range")
    {
        auto source = etl::static_vector<T, 4> {};
        REQUIRE(source.empty());
        etl::stable_sort(begin(source), end(source), etl::less<T> {});
        REQUIRE(source.empty());
    }

    SECTION("already sorted")
    {
        auto source = etl::array<T, 4> { T { 1 }, T { 2 }, T { 3 }, T { 4 } };
        etl::stable_sort(begin(source), end(source));
        REQUIRE(source[0] == T { 1 });
        REQUIRE(source[1] == T { 2 });
        REQUIRE(source[2] == T { 3 });
        REQUIRE(source[3] == T { 4 });
    }

    SECTION("reversed")
    {
        auto source = etl::array<T, 4> { T { 4 }, T { 3 }, T { 2 }, T { 1 } };
        etl::stable_sort(begin(source), end(source));
        REQUIRE(source[0] == T { 1 });
        REQUIRE(source[1] == T { 2 });
        REQUIRE(source[2] == T { 3 });
        REQUIRE(source[3] == T { 4 });
    }
}

TEMPLATE_TEST_CASE("algorithm: partial_sort", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;

    SECTION("empty range")
    {
        auto src = etl::static_vector<T, 4> {};
        REQUIRE(src.empty());
        etl::partial_sort(begin(src), begin(src), end(src), etl::less<T> {});
        REQUIRE(src.empty());
    }

    SECTION("already sorted")
    {
        auto src = etl::array<T, 4> { T { 1 }, T { 2 }, T { 3 }, T { 4 } };
        etl::partial_sort(begin(src), begin(src) + 2, end(src));
        REQUIRE(src[0] == T { 1 });
        REQUIRE(src[1] == T { 2 });
    }

    SECTION("reversed")
    {
        auto src = etl::array<T, 4> { T { 4 }, T { 3 }, T { 2 }, T { 1 } };
        etl::partial_sort(begin(src), begin(src) + 2, end(src));
        REQUIRE(src[0] == T { 1 });
        REQUIRE(src[1] == T { 2 });
    }
}

TEMPLATE_TEST_CASE("algorithm: nth_element", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;

    SECTION("empty range")
    {
        auto src = etl::static_vector<T, 4> {};
        REQUIRE(src.empty());
        etl::nth_element(begin(src), begin(src), end(src));
        REQUIRE(src.empty());
    }

    SECTION("already sorted")
    {
        auto src = etl::array<T, 4> { T { 1 }, T { 2 }, T { 3 }, T { 4 } };
        etl::nth_element(begin(src), begin(src) + 1, end(src), etl::less<> {});
        REQUIRE(src[1] == T { 2 });
    }

    SECTION("reversed")
    {
        auto src = etl::array<T, 4> { T { 4 }, T { 3 }, T { 2 }, T { 1 } };
        etl::nth_element(begin(src), begin(src) + 1, end(src));
        REQUIRE(src[1] == T { 2 });
    }
}

TEMPLATE_TEST_CASE("algorithm: is_sorted", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    SECTION("already is_sorteded")
    {
        auto source = etl::array<TestType, 4> {
            TestType { 1 },
            TestType { 2 },
            TestType { 3 },
            TestType { 4 },
        };

        CHECK(
            etl::is_sorted(begin(source), end(source), etl::less<TestType> {}));
    }

    SECTION("reversed")
    {
        auto source = etl::array<TestType, 4> {
            TestType { 4 },
            TestType { 3 },
            TestType { 2 },
            TestType { 1 },
        };

        CHECK(etl::is_sorted(begin(source), end(source), etl::greater<> {}));
        CHECK_FALSE(etl::is_sorted(begin(source), end(source)));
    }

    SECTION("custom compare")
    {
        auto source = etl::array<TestType, 4> {
            TestType { 1 },
            TestType { 1 },
            TestType { 56 },
            TestType { 42 },
        };

        CHECK_FALSE(
            etl::is_sorted(begin(source), end(source), etl::greater<> {}));
    }
}

TEMPLATE_TEST_CASE("algorithm: is_partitioned", "[algorithm]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;

    SECTION("empty range always returns true")
    {
        auto data      = etl::static_vector<T, 1> {};
        auto predicate = [](auto const& val) { return val < T(1); };
        CHECK(etl::is_partitioned(begin(data), end(data), predicate));
    }

    SECTION("true")
    {
        auto predicate = [](auto const& val) { return val < T(1); };

        auto test1 = etl::array { T(2), T(2), T(2) };
        CHECK(etl::is_partitioned(begin(test1), end(test1), predicate));

        auto test2 = etl::array { T(0), T(0), T(2), T(3) };
        CHECK(etl::is_partitioned(begin(test2), end(test2), predicate));

        auto test3 = etl::array { T(1), T(1), T(2) };
        CHECK(etl::is_partitioned(begin(test3), end(test3), predicate));
    }

    SECTION("false")
    {
        auto predicate = [](auto const& val) { return val < T(1); };

        auto test1 = etl::array { T(2), T(0), T(2) };
        CHECK_FALSE(etl::is_partitioned(begin(test1), end(test1), predicate));

        auto test2 = etl::array { T(0), T(0), T(2), T(0) };
        CHECK_FALSE(etl::is_partitioned(begin(test2), end(test2), predicate));
    }
}
