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

#include "catch2/catch_template_test_macros.hpp"

#include "etl/utility.hpp"

using etl::is_same_v;

TEMPLATE_TEST_CASE("utility: exchange", "[utility]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)

{
  auto original = TestType {42};
  auto const b  = etl::exchange(original, TestType {43});
  REQUIRE(original == TestType {43});
  REQUIRE(b == TestType {42});

  auto const c = etl::exchange(original, TestType {44});
  REQUIRE(original == TestType {44});
  REQUIRE(c == TestType {43});
}

TEMPLATE_TEST_CASE("utility: as_const", "[utility]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)

{
  auto original = TestType {42};
  REQUIRE_FALSE(etl::is_const_v<decltype(original)>);

  auto const& ref = etl::as_const(original);
  REQUIRE(etl::is_const_v<etl::remove_reference_t<decltype(ref)>>);

  REQUIRE(original == 42);
  REQUIRE(original == ref);
}

TEMPLATE_TEST_CASE("utility: cmp_equal", "[utility]", etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
                   etl::int64_t)

{
  REQUIRE(etl::cmp_equal(0, TestType {0}));
  REQUIRE_FALSE(etl::cmp_equal(-1, TestType {0}));

  REQUIRE(etl::cmp_equal(TestType {0}, TestType {0}));
  REQUIRE(etl::cmp_equal(TestType {1}, TestType {1}));
  REQUIRE(etl::cmp_equal(TestType {42}, TestType {42}));

  REQUIRE_FALSE(etl::cmp_equal(TestType {0}, TestType {1}));
  REQUIRE_FALSE(etl::cmp_equal(TestType {1}, TestType {0}));
  REQUIRE_FALSE(etl::cmp_equal(TestType {42}, TestType {43}));
}

TEMPLATE_TEST_CASE("utility: cmp_not_equal", "[utility]", etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
                   etl::int64_t)

{
  REQUIRE(etl::cmp_not_equal(-1, TestType {0}));
  REQUIRE_FALSE(etl::cmp_not_equal(0, TestType {0}));

  REQUIRE_FALSE(etl::cmp_not_equal(TestType {0}, TestType {0}));
  REQUIRE_FALSE(etl::cmp_not_equal(TestType {1}, TestType {1}));
  REQUIRE_FALSE(etl::cmp_not_equal(TestType {42}, TestType {42}));

  REQUIRE(etl::cmp_not_equal(TestType {0}, TestType {1}));
  REQUIRE(etl::cmp_not_equal(TestType {1}, TestType {0}));
  REQUIRE(etl::cmp_not_equal(TestType {42}, TestType {43}));
}

TEMPLATE_TEST_CASE("utility: cmp_less", "[utility]", etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
                   etl::int64_t)

{
  REQUIRE(etl::cmp_less(-1, TestType {0}));
  REQUIRE_FALSE(etl::cmp_less(0, TestType {0}));

  REQUIRE(etl::cmp_less(TestType {0}, TestType {1}));
  REQUIRE(etl::cmp_less(TestType {1}, TestType {2}));
  REQUIRE(etl::cmp_less(TestType {42}, TestType {43}));

  REQUIRE_FALSE(etl::cmp_less(TestType {2}, TestType {1}));
  REQUIRE_FALSE(etl::cmp_less(TestType {1}, TestType {0}));
  REQUIRE_FALSE(etl::cmp_less(TestType {44}, TestType {43}));
}

TEMPLATE_TEST_CASE("utility: cmp_greater", "[utility]", etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
                   etl::int64_t)

{
  REQUIRE_FALSE(etl::cmp_greater(-1, TestType {0}));
  REQUIRE_FALSE(etl::cmp_greater(0, TestType {0}));

  REQUIRE_FALSE(etl::cmp_greater(TestType {0}, TestType {1}));
  REQUIRE_FALSE(etl::cmp_greater(TestType {1}, TestType {2}));
  REQUIRE_FALSE(etl::cmp_greater(TestType {42}, TestType {43}));

  REQUIRE(etl::cmp_greater(TestType {2}, TestType {1}));
  REQUIRE(etl::cmp_greater(TestType {1}, TestType {0}));
  REQUIRE(etl::cmp_greater(TestType {44}, TestType {43}));
}

TEMPLATE_TEST_CASE("utility: cmp_less_equal", "[utility]", etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
                   etl::int64_t)

{
  REQUIRE(etl::cmp_less_equal(-1, TestType {0}));
  REQUIRE(etl::cmp_less_equal(0, TestType {0}));

  REQUIRE(etl::cmp_less_equal(TestType {0}, TestType {1}));
  REQUIRE(etl::cmp_less_equal(TestType {1}, TestType {1}));
  REQUIRE(etl::cmp_less_equal(TestType {1}, TestType {2}));
  REQUIRE(etl::cmp_less_equal(TestType {42}, TestType {43}));

  REQUIRE_FALSE(etl::cmp_less_equal(TestType {2}, TestType {1}));
  REQUIRE_FALSE(etl::cmp_less_equal(TestType {1}, TestType {0}));
  REQUIRE_FALSE(etl::cmp_less_equal(TestType {44}, TestType {43}));
}

TEMPLATE_TEST_CASE("utility: cmp_greater_equal", "[utility]", etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
                   etl::int64_t)

{
  REQUIRE_FALSE(etl::cmp_greater_equal(-1, TestType {0}));
  REQUIRE(etl::cmp_greater_equal(0, TestType {0}));
  REQUIRE(etl::cmp_greater_equal(TestType {0}, 0));

  REQUIRE_FALSE(etl::cmp_greater_equal(TestType {0}, TestType {1}));
  REQUIRE_FALSE(etl::cmp_greater_equal(TestType {1}, TestType {2}));
  REQUIRE_FALSE(etl::cmp_greater_equal(TestType {42}, TestType {43}));

  REQUIRE(etl::cmp_greater_equal(TestType {2}, TestType {2}));
  REQUIRE(etl::cmp_greater_equal(TestType {2}, TestType {1}));
  REQUIRE(etl::cmp_greater_equal(TestType {1}, TestType {0}));
  REQUIRE(etl::cmp_greater_equal(TestType {44}, TestType {43}));
}

TEMPLATE_TEST_CASE("utility: in_range", "[utility]", etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
                   etl::int64_t)

{
  REQUIRE(etl::in_range<TestType>(0));
  REQUIRE(etl::in_range<TestType>(etl::numeric_limits<TestType>::min()));
  REQUIRE(etl::in_range<TestType>(etl::numeric_limits<TestType>::max()));
}

TEMPLATE_TEST_CASE("utility: in_range unsigned", "[utility]", etl::uint16_t,
                   etl::uint32_t, etl::uint64_t)

{
  REQUIRE_FALSE(etl::in_range<TestType>(-1));
}

TEMPLATE_TEST_CASE("utility/pair: default", "[utility]", etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
                   etl::int64_t, float, double, long double)

{
  SECTION("mutable")
  {
    auto p = etl::pair<TestType, int> {};
    STATIC_REQUIRE(is_same_v<TestType, decltype(p.first)>);
    STATIC_REQUIRE(is_same_v<int, decltype(p.second)>);
    REQUIRE(p.first == TestType {});
    REQUIRE(p.second == int {});
  }

  SECTION("const")
  {
    auto const p = etl::pair<TestType, int> {};
    STATIC_REQUIRE(is_same_v<TestType, decltype(p.first)>);
    STATIC_REQUIRE(is_same_v<int, decltype(p.second)>);
    REQUIRE(p.first == TestType {});
    REQUIRE(p.second == int {});
  }

  SECTION("same type twice")
  {
    auto p = etl::pair<TestType, TestType> {};
    STATIC_REQUIRE(is_same_v<TestType, decltype(p.first)>);
    STATIC_REQUIRE(is_same_v<TestType, decltype(p.second)>);
    REQUIRE(p.first == TestType {});
    REQUIRE(p.second == TestType {});
  }

  SECTION("same type twice no auto")
  {
    etl::pair<TestType, TestType> p {};
    STATIC_REQUIRE(is_same_v<TestType, decltype(p.first)>);
    STATIC_REQUIRE(is_same_v<TestType, decltype(p.second)>);
    REQUIRE(p.first == TestType {});
    REQUIRE(p.second == TestType {});
  }
}

TEMPLATE_TEST_CASE("utility/pair: ctad", "[utility]", etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
                   etl::int64_t, float, double, long double)

{
  auto p1 = etl::pair {TestType {0}, 143.0F};
  STATIC_REQUIRE(is_same_v<TestType, decltype(p1.first)>);
  STATIC_REQUIRE(is_same_v<float, decltype(p1.second)>);
  REQUIRE(p1.first == 0);
  REQUIRE(p1.second == 143.0);

  auto p2 = etl::pair {1.2, TestType {42}};
  STATIC_REQUIRE(is_same_v<double, decltype(p2.first)>);
  STATIC_REQUIRE(is_same_v<TestType, decltype(p2.second)>);
  REQUIRE(p2.first == 1.2);
  REQUIRE(p2.second == TestType {42});

  auto p3 = etl::pair {TestType {2}, TestType {42}};
  STATIC_REQUIRE(is_same_v<TestType, decltype(p3.first)>);
  STATIC_REQUIRE(is_same_v<TestType, decltype(p3.second)>);
  REQUIRE(p3.first == TestType {2});
  REQUIRE(p3.second == TestType {42});
}

TEMPLATE_TEST_CASE("utility/pair: copy construct", "[utility]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)

{
  SECTION("same types")
  {
    auto p = etl::make_pair(TestType {0}, 143.0F);
    auto other {p};

    STATIC_REQUIRE(is_same_v<decltype(other.first), decltype(p.first)>);
    STATIC_REQUIRE(is_same_v<decltype(other.second), decltype(p.second)>);

    REQUIRE(other.first == p.first);
    REQUIRE(other.second == p.second);
  }

  SECTION("different types")
  {
    auto p     = etl::make_pair(TestType {0}, 143.0F);
    auto other = etl::pair<TestType, double> {p};

    STATIC_REQUIRE(is_same_v<decltype(other.first), decltype(p.first)>);
    STATIC_REQUIRE_FALSE(is_same_v<decltype(other.second), decltype(p.second)>);

    REQUIRE(other.first == p.first);
    REQUIRE(other.second == p.second);
  }
}

TEMPLATE_TEST_CASE("utility/pair: move construct", "[utility]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)

{
  SECTION("same types")
  {
    auto p = etl::make_pair(TestType {0}, 143.0F);
    auto other {etl::move(p)};

    STATIC_REQUIRE(is_same_v<decltype(other.first), decltype(p.first)>);
    STATIC_REQUIRE(is_same_v<decltype(other.second), decltype(p.second)>);

    REQUIRE(other.first == p.first);
    REQUIRE(other.second == p.second);
  }

  SECTION("different types")
  {
    auto p     = etl::make_pair(TestType {0}, 143.0F);
    auto other = etl::pair<TestType, double> {etl::move(p)};

    STATIC_REQUIRE(is_same_v<decltype(other.first), decltype(p.first)>);
    STATIC_REQUIRE_FALSE(is_same_v<decltype(other.second), decltype(p.second)>);

    REQUIRE(other.first == p.first);
    REQUIRE(other.second == p.second);
  }
}

TEMPLATE_TEST_CASE("utility/pair: copy assign", "[utility]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)

{
  auto p = etl::make_pair(TestType {0}, 143.0F);
  SECTION("same types")
  {
    auto other = etl::pair<TestType, float> {};
    other      = p;
    REQUIRE(other.first == p.first);
    REQUIRE(other.second == p.second);
  }
  SECTION("different types")
  {
    auto other = etl::pair<TestType, double> {};
    other      = p;

    STATIC_REQUIRE(is_same_v<decltype(other.first), decltype(p.first)>);
    STATIC_REQUIRE_FALSE(is_same_v<decltype(other.second), decltype(p.second)>);

    REQUIRE(other.first == p.first);
    REQUIRE(other.second == (float)p.second);
  }
}

TEMPLATE_TEST_CASE("utility/pair: move assign", "[utility]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)

{
  auto p = etl::make_pair(TestType {0}, 143.0F);
  SECTION("same types")
  {
    auto other = etl::pair<TestType, float> {};
    other      = etl::move(p);
    REQUIRE(other.first == p.first);
    REQUIRE(other.second == p.second);
  }
  SECTION("different types")
  {
    auto other = etl::pair<TestType, double> {};
    other      = etl::move(p);

    STATIC_REQUIRE(is_same_v<decltype(other.first), decltype(p.first)>);
    STATIC_REQUIRE_FALSE(is_same_v<decltype(other.second), decltype(p.second)>);

    REQUIRE(other.first == p.first);
    REQUIRE(other.second == (float)p.second);
  }
}

TEMPLATE_TEST_CASE("utility/pair: make_pair", "[utility]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)

{
  auto p = etl::make_pair(TestType {0}, 143.0F);
  STATIC_REQUIRE(is_same_v<TestType, decltype(p.first)>);
  STATIC_REQUIRE(is_same_v<float, decltype(p.second)>);

  REQUIRE(p.first == 0);
  REQUIRE(p.second == 143.0);
}

TEMPLATE_TEST_CASE("utility/pair: swap", "[utility]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)

{
  using pair_type = etl::pair<TestType, int>;
  using etl::swap;

  SECTION("empty")
  {
    auto lhs = pair_type();
    auto rhs = pair_type();
    CHECK(lhs.first == TestType());
    CHECK(lhs == rhs);

    swap(lhs, rhs);
    CHECK(lhs.first == TestType());
    CHECK(lhs == rhs);
  }

  SECTION("not empty")
  {
    auto lhs = pair_type();
    auto rhs = pair_type(TestType(42), 143);
    CHECK(lhs.first == TestType());

    swap(lhs, rhs);
    CHECK(lhs.first == TestType(42));
    CHECK(lhs.second == 143);

    swap(lhs, rhs);
    CHECK(rhs.first == TestType(42));
    CHECK(rhs.second == 143);
  }
}

TEMPLATE_TEST_CASE("utility/pair: operator==", "[utility]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)

{
  auto const p1 = etl::make_pair(TestType {42}, 143.0F);
  auto const p2 = etl::make_pair(TestType {42}, 143.0F);
  auto const p3 = etl::make_pair(TestType {123}, 143.0F);

  REQUIRE(p1 == p2);
  REQUIRE(p2 == p1);

  REQUIRE_FALSE(p3 == p2);
  REQUIRE_FALSE(p3 == p1);
}

TEMPLATE_TEST_CASE("utility/pair: operator!=", "[utility]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)

{
  auto const p1 = etl::make_pair(TestType {42}, 143.0F);
  auto const p2 = etl::make_pair(TestType {42}, 143.0F);
  auto const p3 = etl::make_pair(TestType {123}, 143.0F);

  REQUIRE_FALSE(p1 != p2);
  REQUIRE_FALSE(p2 != p1);

  REQUIRE(p3 != p2);
  REQUIRE(p3 != p1);
}

TEMPLATE_TEST_CASE("utility/pair: operator<", "[utility]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)

{
  auto const p1 = etl::make_pair(TestType {42}, 143.0F);
  auto const p2 = etl::make_pair(TestType {42}, 143.0F);
  auto const p3 = etl::make_pair(TestType {123}, 143.0F);

  REQUIRE_FALSE(p1 < p2);
  REQUIRE_FALSE(p2 < p1);

  REQUIRE(p2 < p3);
  REQUIRE(p1 < p3);
}

TEMPLATE_TEST_CASE("utility/pair: operator<=", "[utility]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)

{
  auto const p1 = etl::make_pair(TestType {42}, 143.0F);
  auto const p2 = etl::make_pair(TestType {42}, 143.0F);
  auto const p3 = etl::make_pair(TestType {123}, 143.0F);

  REQUIRE(p1 <= p2);
  REQUIRE(p2 <= p1);

  REQUIRE(p2 <= p3);
  REQUIRE(p1 <= p3);
}

TEMPLATE_TEST_CASE("utility/pair: operator>", "[utility]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)

{
  auto const p1 = etl::make_pair(TestType {42}, 143.0F);
  auto const p2 = etl::make_pair(TestType {24}, 143.0F);
  auto const p3 = etl::make_pair(TestType {123}, 143.0F);

  REQUIRE(p1 > p2);
  REQUIRE_FALSE(p2 > p1);

  REQUIRE_FALSE(p2 > p3);
  REQUIRE_FALSE(p1 > p3);
}

TEMPLATE_TEST_CASE("utility/pair: operator>=", "[utility]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)

{
  auto const p1 = etl::make_pair(TestType {42}, 143.0F);
  auto const p2 = etl::make_pair(TestType {24}, 143.0F);
  auto const p3 = etl::make_pair(TestType {123}, 143.0F);

  REQUIRE(p1 >= p2);
  REQUIRE_FALSE(p2 >= p1);

  REQUIRE_FALSE(p2 >= p3);
  REQUIRE_FALSE(p1 >= p3);
}

TEMPLATE_TEST_CASE("utility/pair: tuple_size", "[utility]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)

{
  STATIC_REQUIRE(etl::tuple_size<etl::pair<TestType, TestType>>::value == 2);
  STATIC_REQUIRE(etl::tuple_size_v<etl::pair<TestType, TestType>> == 2);

  STATIC_REQUIRE(etl::tuple_size<etl::pair<TestType, float>>::value == 2);
  STATIC_REQUIRE(etl::tuple_size_v<etl::pair<TestType, float>> == 2);

  STATIC_REQUIRE(etl::tuple_size<etl::pair<float, TestType>>::value == 2);
  STATIC_REQUIRE(etl::tuple_size_v<etl::pair<float, TestType>> == 2);
}

TEMPLATE_TEST_CASE("utility/pair: tuple_element", "[utility]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)

{
  using etl::tuple_element_t;
  auto p = etl::pair<TestType, float> {TestType {42}, 143.0F};
  STATIC_REQUIRE(is_same_v<TestType, tuple_element_t<0, decltype(p)>>);
  STATIC_REQUIRE(is_same_v<float, tuple_element_t<1, decltype(p)>>);
}