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

#include "etl/optional.hpp"

TEMPLATE_TEST_CASE("optional: construct()", "[optional]", bool, etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double)
{
  CHECK_FALSE(etl::optional<TestType> {}.has_value());
  CHECK_FALSE(etl::optional<TestType> {etl::nullopt}.has_value());
}

TEMPLATE_TEST_CASE("optional: construct(value_type)", "[optional]", bool,
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double)
{
  CHECK(etl::optional<TestType> {TestType {}}.has_value());
  CHECK(etl::optional<TestType> {TestType {1}}.has_value());
}

TEMPLATE_TEST_CASE("optional: construct(in_place, args...)", "[optional]", bool,
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double)
{
  auto opt = etl::optional<TestType> {etl::in_place, TestType {}};
  CHECK(opt.has_value());
}

TEMPLATE_TEST_CASE("optional: construct(optional)", "[optional]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double)
{
  SECTION("empty")
  {
    etl::optional<TestType> opt {};
    CHECK_FALSE(opt.has_value());

    // copy ctor
    auto opt_1 {opt};
    CHECK_FALSE(opt_1.has_value());

    // move ctor
    auto opt_2 {etl::move(opt)};
    CHECK_FALSE(opt_2.has_value());

    auto opt_3 {etl::optional<TestType> {}};
    CHECK_FALSE(opt_3.has_value());
  }

  SECTION("with value")
  {
    auto opt = etl::optional<TestType> {TestType {42}};
    CHECK(opt.has_value());
    CHECK(*opt.value() == TestType {42});

    // copy ctor
    auto opt_1 {opt};
    CHECK(opt_1.has_value());
    CHECK(*opt_1.value() == TestType {42});

    // move ctor
    auto opt_2 {etl::move(opt)};
    CHECK(opt_2.has_value());
    CHECK(*opt_2.value() == TestType {42});

    auto opt_3 {etl::optional<TestType> {TestType {42}}};
    CHECK(opt_3.has_value());
    CHECK(*opt_3.value() == TestType {42});
  }
}

TEST_CASE("optional: construct() non_trivial", "[optional]")
{
  struct S
  {
    S() = default;
    S(S const&) { }
    S(S&&) { }
    S& operator=(S const&) { return *this; }
    S& operator=(S&&) { return *this; }
    ~S() { }
  };

  STATIC_REQUIRE_FALSE(etl::is_trivially_destructible_v<S>);
  STATIC_REQUIRE_FALSE(etl::is_trivially_move_assignable_v<S>);
  STATIC_REQUIRE_FALSE(etl::is_trivially_move_constructible_v<S>);

  etl::optional<S> opt_1 {S {}};
  CHECK(opt_1.has_value());

  {
    auto opt_2 {opt_1};
    CHECK(opt_2.has_value());

    auto const opt_3 {etl::move(opt_2)};
    CHECK(opt_3.has_value());

    auto const opt_4 {opt_3};
    CHECK(opt_4.has_value());
  }
}

TEMPLATE_TEST_CASE("optional: operator=(nullopt)", "[optional]", bool,
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double)
{
  etl::optional<TestType> opt {};
  CHECK_FALSE(opt.has_value());
  opt = etl::nullopt;
  CHECK_FALSE(opt.has_value());
}

TEMPLATE_TEST_CASE("optional: operator=(value_type)", "[optional]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double)
{
  SECTION("empty")
  {
    etl::optional<TestType> opt {};
    CHECK_FALSE(opt.has_value());
    opt = TestType {42};
    CHECK(opt.has_value());
    CHECK(*opt.value() == TestType {42});
  }

  SECTION("with value")
  {
    etl::optional<TestType> opt {TestType {}};
    CHECK(opt.has_value());
    CHECK(*opt.value() == TestType {});

    opt = TestType {42};
    CHECK(opt.has_value());
    CHECK(*opt.value() == TestType {42});
  }
}

TEMPLATE_TEST_CASE("optional: operator=(optional)", "[optional]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double)
{
  SECTION("None have values")
  {
    etl::optional<TestType> opt {};
    CHECK_FALSE(opt.has_value());

    // copy assignment
    opt = etl::optional<TestType> {};
    CHECK_FALSE(opt.has_value());

    // move assignment
    opt = etl::move(etl::optional<TestType> {});
    CHECK_FALSE(opt.has_value());
  }

  SECTION("First has value")
  {
    etl::optional<TestType> opt {TestType {42}};
    CHECK(opt.has_value());
    CHECK(*opt.value() == TestType {42});
    opt = etl::optional<TestType> {};
    CHECK_FALSE(opt.has_value());
  }

  SECTION("Second has value")
  {
    etl::optional<TestType> opt {};
    CHECK_FALSE(opt.has_value());
    opt = etl::optional<TestType> {TestType {42}};
    CHECK(opt.has_value());
    CHECK(*opt.value() == TestType {42});
  }
}

TEST_CASE("optional: operator=() non_trivial", "[optional]")
{
  struct S
  {
    S() = default;
    S(S const&) { }
    S(S&&) { }
    S& operator=(S const&) { return *this; }
    S& operator=(S&&) { return *this; }
    ~S() { }
  };

  STATIC_REQUIRE_FALSE(etl::is_trivially_destructible_v<S>);
  STATIC_REQUIRE_FALSE(etl::is_trivially_move_assignable_v<S>);
  STATIC_REQUIRE_FALSE(etl::is_trivially_move_constructible_v<S>);

  etl::optional<S> opt_1 {};
  CHECK_FALSE(opt_1.has_value());

  opt_1 = S {};
  CHECK(opt_1.has_value());

  {
    auto opt_2 = opt_1;
    CHECK(opt_2.has_value());

    auto const opt_3 = etl::move(opt_2);
    CHECK(opt_3.has_value());

    auto const opt_4 = opt_3;
    CHECK(opt_4.has_value());
  }
}

TEMPLATE_TEST_CASE("optional: is_trivially_destructible_v", "[optional]", bool,
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double)
{
  SECTION("true")
  {
    etl::optional<TestType> opt {};
    STATIC_REQUIRE(etl::is_trivially_destructible_v<decltype(opt)>);
  }

  SECTION("false")
  {
    struct S
    {
      S() = default;
      ~S() { }

      TestType data {};
    };

    etl::optional<S> opt {};
    STATIC_REQUIRE_FALSE(etl::is_trivially_destructible_v<S>);
  }
}

TEMPLATE_TEST_CASE("optional: has_value", "[optional]", bool, etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double)
{
  SECTION("empty")
  {
    auto opt = etl::optional<TestType> {};
    CHECK_FALSE(opt.has_value());

    auto const c_opt = etl::optional<TestType> {};
    CHECK_FALSE(c_opt.has_value());
  }

  SECTION("with value")
  {
    auto opt = etl::optional<TestType> {TestType {1}};
    CHECK(opt.has_value());

    auto const c_opt = etl::optional<TestType> {TestType {1}};
    CHECK(c_opt.has_value());
  }
}

TEMPLATE_TEST_CASE("optional: operator bool", "[optional]", bool, etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double)
{
  SECTION("empty")
  {
    auto opt = etl::optional<TestType> {};
    CHECK_FALSE(static_cast<bool>(opt));

    auto const c_opt = etl::optional<TestType> {};
    CHECK_FALSE(static_cast<bool>(c_opt));
  }

  SECTION("with value")
  {
    auto opt = etl::optional<TestType> {TestType {1}};
    CHECK(static_cast<bool>(opt));

    auto const c_opt = etl::optional<TestType> {TestType {1}};
    CHECK(static_cast<bool>(c_opt));
  }
}

TEMPLATE_TEST_CASE("optional: operator->()", "[optional]", bool, etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double)
{
  SECTION("empty")
  {
    auto opt = etl::optional<TestType> {};
    CHECK(opt.operator->() == nullptr);

    auto const c_opt = etl::optional<TestType> {};
    CHECK(c_opt.operator->() == nullptr);
  }

  SECTION("with value")
  {
    auto opt = etl::optional<TestType> {TestType {1}};
    CHECK_FALSE(opt.operator->() == nullptr);

    auto const c_opt = etl::optional<TestType> {TestType {1}};
    CHECK_FALSE(c_opt.operator->() == nullptr);
  }
}

TEMPLATE_TEST_CASE("optional: value_or", "[optional]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double)
{
  SECTION("empty")
  {
    auto opt = etl::optional<TestType> {};
    CHECK(opt.value_or(TestType {42}) == TestType {42});

    auto const c_opt = etl::optional<TestType> {};
    CHECK(c_opt.value_or(TestType {42}) == TestType {42});

    CHECK(etl::optional<TestType> {}.value_or(TestType {42}) == TestType {42});
    CHECK(
      etl::move(etl::optional<TestType> {etl::nullopt}).value_or(TestType {42})
      == TestType {42});
  }

  SECTION("with value")
  {
    auto opt = etl::optional<TestType> {TestType {1}};
    CHECK(opt.value_or(TestType {42}) == TestType {1});

    auto const c_opt = etl::optional<TestType> {TestType {1}};
    CHECK(c_opt.value_or(TestType {42}) == TestType {1});

    CHECK(etl::optional<TestType> {TestType {1}}.value_or(TestType {42})
          == TestType {1});

    CHECK(
      etl::move(etl::optional<TestType> {TestType {1}}).value_or(TestType {42})
      == TestType {1});
  }
}

TEMPLATE_TEST_CASE("optional: reset", "[optional]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double)
{
  SECTION("empty")
  {
    etl::optional<TestType> opt {};
    CHECK_FALSE(opt.has_value());
    opt.reset();
    CHECK_FALSE(opt.has_value());
  }

  SECTION("with trivial value")
  {
    etl::optional<TestType> opt {TestType {}};
    CHECK(opt.has_value());
    opt.reset();
    CHECK_FALSE(opt.has_value());
  }

  SECTION("with none-trivial value")
  {
    struct S
    {
      int& counter;

      S(int& c) : counter {c} { }
      ~S() { counter++; }
    };

    auto counter = 0;
    etl::optional<S> opt {etl::in_place, counter};
    CHECK(opt.has_value());
    CHECK(counter == 0);
    opt.reset();
    CHECK_FALSE(opt.has_value());
    CHECK(counter == 1);
  }
}

TEMPLATE_TEST_CASE("optional: emplace", "[optional]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double)
{
  struct S
  {
    S(TestType _x, TestType _y) : x {_x}, y {_y} { }

    TestType x;
    TestType y;
  };

  SECTION("built-in types")
  {
    etl::optional<TestType> opt {};
    CHECK_FALSE(opt.has_value());
    opt.emplace(TestType {1});
    CHECK(opt.has_value());
  }

  SECTION("struct")
  {
    etl::optional<S> opt {};
    CHECK_FALSE(opt.has_value());
    opt.emplace(TestType {1}, TestType {2});
    CHECK(opt.has_value());
  }
}

TEMPLATE_TEST_CASE("optional: operator== & operator!=", "[optional]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double)
{
  SECTION("empty")
  {
    etl::optional<TestType> lhs_1 {};
    etl::optional<TestType> rhs_1 {};
    CHECK(lhs_1 == rhs_1);
    CHECK_FALSE(lhs_1 != rhs_1);

    etl::optional<TestType> lhs_2 {etl::nullopt};
    etl::optional<TestType> rhs_2 {etl::nullopt};
    CHECK(lhs_2 == rhs_2);
    CHECK(lhs_2 == etl::nullopt);
    CHECK(etl::nullopt == rhs_2);
    CHECK_FALSE(lhs_2 != rhs_2);
  }

  SECTION("with value")
  {
    etl::optional<TestType> lhs_1 {TestType {42}};
    etl::optional<TestType> rhs_1 {TestType {42}};
    CHECK(lhs_1 == rhs_1);
    CHECK_FALSE(lhs_1 != rhs_1);
    CHECK_FALSE(lhs_1 == etl::nullopt);
    CHECK_FALSE(etl::nullopt == lhs_1);

    etl::optional<TestType> lhs_2 {TestType {0}};
    etl::optional<TestType> rhs_2 {TestType {42}};
    CHECK(lhs_2 != rhs_2);
    CHECK(lhs_2 != etl::nullopt);
    CHECK(etl::nullopt != lhs_2);
    CHECK_FALSE(lhs_2 == rhs_2);

    etl::optional<TestType> lhs_3 {TestType {0}};
    etl::optional<TestType> rhs_3 {etl::nullopt};
    CHECK(lhs_3 != rhs_3);
    CHECK_FALSE(lhs_3 == rhs_3);
  }
}

TEMPLATE_TEST_CASE("optional: operator<", "[optional]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double)
{
  SECTION("empty")
  {
    etl::optional<TestType> lhs_1 {};
    etl::optional<TestType> rhs_1 {};
    CHECK_FALSE(lhs_1 < rhs_1);
    CHECK_FALSE(etl::nullopt < rhs_1);
    CHECK_FALSE(lhs_1 < etl::nullopt);

    etl::optional<TestType> lhs_2 {etl::nullopt};
    etl::optional<TestType> rhs_2 {etl::nullopt};
    CHECK_FALSE(lhs_2 < rhs_2);
  }

  SECTION("with value")
  {
    etl::optional<TestType> lhs_1 {TestType {42}};
    etl::optional<TestType> rhs_1 {TestType {42}};
    CHECK_FALSE(lhs_1 < rhs_1);
    CHECK_FALSE(lhs_1 < etl::nullopt);
    CHECK(etl::nullopt < rhs_1);

    etl::optional<TestType> lhs_2 {TestType {0}};
    etl::optional<TestType> rhs_2 {TestType {42}};
    CHECK(lhs_2 < rhs_2);

    etl::optional<TestType> lhs_3 {etl::nullopt};
    etl::optional<TestType> rhs_3 {TestType {42}};
    CHECK(lhs_3 < rhs_3);

    CHECK(etl::nullopt < rhs_3);
    CHECK_FALSE(lhs_3 < etl::nullopt);
  }
}

TEMPLATE_TEST_CASE("optional: operator>", "[optional]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double)
{
  SECTION("empty")
  {
    etl::optional<TestType> lhs_1 {};
    etl::optional<TestType> rhs_1 {};
    CHECK_FALSE(lhs_1 > rhs_1);

    etl::optional<TestType> lhs_2 {etl::nullopt};
    etl::optional<TestType> rhs_2 {etl::nullopt};
    CHECK_FALSE(lhs_2 > rhs_2);
  }

  SECTION("with value")
  {
    etl::optional<TestType> lhs_1 {TestType {42}};
    etl::optional<TestType> rhs_1 {TestType {42}};
    CHECK_FALSE(lhs_1 > rhs_1);

    etl::optional<TestType> lhs_2 {TestType {42}};
    etl::optional<TestType> rhs_2 {TestType {0}};
    CHECK(lhs_2 > rhs_2);
  }
}

TEMPLATE_TEST_CASE("optional: operator<=", "[optional]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double)
{
  SECTION("empty")
  {
    etl::optional<TestType> lhs_1 {};
    etl::optional<TestType> rhs_1 {};
    CHECK(lhs_1 <= rhs_1);

    etl::optional<TestType> lhs_2 {etl::nullopt};
    etl::optional<TestType> rhs_2 {etl::nullopt};
    CHECK(lhs_2 <= rhs_2);
  }

  SECTION("with value")
  {
    etl::optional<TestType> lhs_1 {TestType {42}};
    etl::optional<TestType> rhs_1 {TestType {42}};
    CHECK(lhs_1 <= rhs_1);

    etl::optional<TestType> lhs_2 {TestType {0}};
    etl::optional<TestType> rhs_2 {TestType {42}};
    CHECK(lhs_2 <= rhs_2);

    etl::optional<TestType> lhs_3 {etl::nullopt};
    etl::optional<TestType> rhs_3 {TestType {42}};
    CHECK(lhs_3 <= rhs_3);
  }
}

TEMPLATE_TEST_CASE("optional: operator>=", "[optional]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double)
{
  SECTION("empty")
  {
    etl::optional<TestType> lhs_1 {};
    etl::optional<TestType> rhs_1 {};
    CHECK(lhs_1 >= rhs_1);

    etl::optional<TestType> lhs_2 {etl::nullopt};
    etl::optional<TestType> rhs_2 {etl::nullopt};
    CHECK(lhs_2 >= rhs_2);
  }

  SECTION("with value")
  {
    etl::optional<TestType> lhs_1 {TestType {42}};
    etl::optional<TestType> rhs_1 {TestType {42}};
    CHECK(lhs_1 >= rhs_1);
    CHECK(rhs_1 >= lhs_1);

    etl::optional<TestType> lhs_2 {TestType {42}};
    etl::optional<TestType> rhs_2 {TestType {0}};
    CHECK(lhs_2 >= rhs_2);
    CHECK_FALSE(rhs_2 >= lhs_2);
  }
}

TEMPLATE_TEST_CASE("optional: swap", "[optional]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double)
{
  SECTION("empty")
  {
    etl::optional<TestType> opt_1 {};
    etl::optional<TestType> opt_2 {};
    CHECK_FALSE(opt_1.has_value());
    CHECK_FALSE(opt_2.has_value());

    opt_1.swap(opt_2);
    CHECK_FALSE(opt_1.has_value());
    CHECK_FALSE(opt_2.has_value());
  }

  SECTION("with trivial value")
  {
    SECTION("One Side")
    {
      etl::optional<TestType> opt_1 {TestType {1}};
      etl::optional<TestType> opt_2 {};
      CHECK(opt_1.has_value());
      CHECK_FALSE(opt_2.has_value());

      opt_1.swap(opt_2);
      CHECK_FALSE(opt_1.has_value());
      CHECK(opt_2.has_value());
      CHECK(*opt_2.value() == 1);

      etl::optional<TestType> opt_3 {};
      etl::optional<TestType> opt_4 {TestType {1}};
      CHECK_FALSE(opt_3.has_value());
      CHECK(opt_4.has_value());

      opt_3.swap(opt_4);
      CHECK(opt_3.has_value());
      CHECK(*opt_3.value() == 1);
      CHECK_FALSE(opt_4.has_value());
    }

    SECTION("Both Sides")
    {
      etl::optional<TestType> opt_1 {TestType {1}};
      etl::optional<TestType> opt_2 {TestType {2}};
      CHECK(opt_1.has_value());
      CHECK(opt_2.has_value());

      opt_1.swap(opt_2);
      CHECK(opt_1.has_value());
      CHECK(opt_2.has_value());
      CHECK(*opt_1.value() == 2);
      CHECK(*opt_2.value() == 1);
    }
  }

  SECTION("with none-trivial value")
  {
    struct S
    {
      TestType data;

      S(TestType c) : data {c} { }
      ~S() { }
    };

    etl::optional<S> opt_1 {TestType {1}};
    etl::optional<S> opt_2 {TestType {2}};
    CHECK(opt_1.has_value());
    CHECK(opt_2.has_value());

    opt_1.swap(opt_2);
    CHECK(opt_1.has_value());
    CHECK(opt_2.has_value());
    CHECK(opt_1.value()->data == 2);
    CHECK(opt_2.value()->data == 1);
  }
}

TEMPLATE_TEST_CASE("optional: make_optional(value_type)", "[optional]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double)
{
  auto opt_1 = etl::make_optional(TestType {42});
  STATIC_REQUIRE(
    etl::is_same_v<typename decltype(opt_1)::value_type, TestType>);

  auto value_2 = TestType {};
  auto opt_2   = etl::make_optional(TestType {value_2});
  STATIC_REQUIRE(
    etl::is_same_v<typename decltype(opt_2)::value_type, TestType>);

  auto const value_3 = TestType {};
  auto const opt_3   = etl::make_optional(TestType {value_3});
  STATIC_REQUIRE(
    etl::is_same_v<typename decltype(opt_3)::value_type, TestType>);
}

TEMPLATE_TEST_CASE("optional: make_optional(args...)", "[optional]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double)
{
  struct S
  {
    TestType data_1;
    int data_2;

    S(TestType d1, int d2) : data_1 {d1}, data_2 {d2} { }
  };

  auto const opt = etl::make_optional<S>(TestType {42}, 1);
  STATIC_REQUIRE(etl::is_same_v<typename decltype(opt)::value_type, S>);

  CHECK(opt.value()->data_1 == TestType {42});
  CHECK(opt.value()->data_2 == 1);
}

TEMPLATE_TEST_CASE("optional: deduction guide", "[optional]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double)
{
  SECTION("implicit")
  {
    {
      etl::optional opt {TestType {}};
      STATIC_REQUIRE(
        etl::is_same_v<typename decltype(opt)::value_type, TestType>);
    }

    {
      TestType data {};
      etl::optional opt {data};
      STATIC_REQUIRE(
        etl::is_same_v<typename decltype(opt)::value_type, TestType>);
    }

    {
      TestType const data {42};
      etl::optional opt {data};
      STATIC_REQUIRE(
        etl::is_same_v<typename decltype(opt)::value_type, TestType>);
    }
  }

  SECTION("explicit")
  {
    TestType data[2];
    etl::optional opt {data};  // explicit deduction guide is used in this case
    STATIC_REQUIRE(
      etl::is_same_v<typename decltype(opt)::value_type, TestType*>);
  }
}
