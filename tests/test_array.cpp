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

#include "catch2/catch_template_test_macros.hpp"

#include "etl/algorithm.hpp"
#include "etl/array.hpp"
#include "etl/numeric.hpp"

TEMPLATE_TEST_CASE("array: construct default", "[array]", etl::uint8_t, etl::int8_t, etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t, float,
                   double, long double)
{
  etl::array<TestType, 2> arr {};

  REQUIRE(arr.empty() == false);
  REQUIRE(arr[0] == TestType {0});
  REQUIRE(arr[1] == TestType {0});
}

TEMPLATE_TEST_CASE("array: deduction guide", "[array]", etl::uint8_t, etl::int8_t, etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t, float,
                   double, long double)
{
  auto const x = TestType {10};
  auto a       = etl::array {TestType {1}, TestType {2}, x};
  REQUIRE(a.size() == 3);
}

TEMPLATE_TEST_CASE("array: size", "[array]", etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)
{
  etl::array<TestType, 4> arr {};
  REQUIRE(arr.size() == arr.max_size());
  REQUIRE(arr.size() == 4);
}

TEMPLATE_TEST_CASE("array: range-for", "[array]", etl::uint8_t, etl::int8_t, etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t)
{
  etl::array<TestType, 4> arr {};
  etl::iota(etl::begin(arr), etl::end(arr), TestType {0});

  auto counter = 0;
  for (auto& x : arr) { REQUIRE(x == static_cast<TestType>(counter++)); }
}

TEMPLATE_TEST_CASE("array: range-for-const", "[array]", etl::uint8_t, etl::int8_t, etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t)
{
  etl::array<TestType, 4> arr {};
  etl::iota(etl::begin(arr), etl::end(arr), TestType {0});

  REQUIRE(*arr.data() == 0);
  REQUIRE(arr.front() == 0);
  REQUIRE(arr.back() == TestType {3});

  auto counter = 0;
  for (auto const& x : arr) { REQUIRE(x == static_cast<TestType>(counter++)); }
}

TEMPLATE_TEST_CASE("array: begin/end", "[array]", etl::uint8_t, etl::int8_t, etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t)
{
  SECTION("const")
  {
    auto const arr = []()
    {
      etl::array<TestType, 4> a {};
      etl::iota(etl::begin(a), etl::end(a), TestType {0});
      return a;
    }();

    REQUIRE(*arr.data() == 0);

    auto counter = 0;
    for (auto const& x : arr) { REQUIRE(x == static_cast<TestType>(counter++)); }
  }
}

TEMPLATE_TEST_CASE("array: rbegin/rend", "[array]", etl::uint8_t, etl::int8_t, etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t)
{
  SECTION("mutable")
  {
    auto arr = etl::array {TestType(1), TestType(2), TestType(3)};
    auto it  = arr.rbegin();

    CHECK(*it == TestType(3));
    ++it;
    CHECK(*it == TestType(2));
    it++;
    CHECK(*it == TestType(1));
  }

  SECTION("const")
  {
    auto const arr = etl::array {TestType(1), TestType(2), TestType(3)};
    auto it        = arr.rbegin();

    CHECK(*it == TestType(3));
    ++it;
    CHECK(*it == TestType(2));
    it++;
    CHECK(*it == TestType(1));
  }
}

TEMPLATE_TEST_CASE("array: at", "[array]", etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)
{
  auto arr = []()
  {
    etl::array<TestType, 4> a {};
    etl::iota(etl::begin(a), etl::end(a), TestType {0});
    return a;
  }();

  REQUIRE(arr.at(0) == TestType {0});
  REQUIRE(arr.at(1) == TestType {1});
  REQUIRE(arr.at(2) == TestType {2});
  REQUIRE(arr.at(3) == TestType {3});

  REQUIRE(arr[0] == TestType {0});
  REQUIRE(arr[1] == TestType {1});
  REQUIRE(arr[2] == TestType {2});
  REQUIRE(arr[3] == TestType {3});
}

TEMPLATE_TEST_CASE("array: at const", "[array]", etl::uint8_t, etl::int8_t, etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t)
{
  auto const arr = []()
  {
    etl::array<TestType, 4> a {};
    etl::iota(etl::begin(a), etl::end(a), TestType {0});
    return a;
  }();

  REQUIRE(arr.at(0) == TestType {0});
  REQUIRE(arr.at(1) == TestType {1});
  REQUIRE(arr.at(2) == TestType {2});
  REQUIRE(arr.at(3) == TestType {3});

  REQUIRE(arr[0] == TestType {0});
  REQUIRE(arr[1] == TestType {1});
  REQUIRE(arr[2] == TestType {2});
  REQUIRE(arr[3] == TestType {3});
}

TEMPLATE_TEST_CASE("array: front/back", "[array]", etl::uint8_t, etl::int8_t, etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t)
{
  auto arr = []()
  {
    etl::array<TestType, 4> a {};
    etl::iota(etl::begin(a), etl::end(a), TestType {0});
    return a;
  }();

  REQUIRE(arr.front() == 0);
  REQUIRE(arr.back() == 3);
}

TEMPLATE_TEST_CASE("array: front/back const", "[array]", etl::uint8_t, etl::int8_t, etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t)
{
  auto const arr = []()
  {
    etl::array<TestType, 4> a {};
    etl::iota(etl::begin(a), etl::end(a), TestType {0});
    return a;
  }();

  REQUIRE(arr.front() == 0);
  REQUIRE(arr.back() == 3);
}

TEMPLATE_TEST_CASE("array: fill", "[array]", etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)
{
  etl::array<TestType, 4> arr {};
  REQUIRE(etl::all_of(begin(arr), end(arr), [](auto const& val) { return val == 0; }));

  arr.fill(TestType {42});
  REQUIRE(etl::all_of(begin(arr), end(arr), [](auto const& val) { return val == 42; }));

  arr.fill(TestType {1});
  REQUIRE(etl::all_of(begin(arr), end(arr), [](auto const& val) { return val == 1; }));
}

TEMPLATE_TEST_CASE("array: swap", "[array]", etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)
{
  etl::array<TestType, 4> a {};
  a.fill(TestType {1});
  etl::array<TestType, 4> b {};

  REQUIRE(etl::all_of(begin(a), end(a), [](auto const& val) { return val == 1; }));
  REQUIRE(etl::all_of(begin(b), end(b), [](auto const& val) { return val == 0; }));

  a.swap(b);
  REQUIRE(etl::all_of(begin(a), end(a), [](auto const& val) { return val == 0; }));
  REQUIRE(etl::all_of(begin(b), end(b), [](auto const& val) { return val == 1; }));

  etl::swap(a, b);
  REQUIRE(etl::all_of(begin(a), end(a), [](auto const& val) { return val == 1; }));
  REQUIRE(etl::all_of(begin(b), end(b), [](auto const& val) { return val == 0; }));
}

TEMPLATE_TEST_CASE("array: comparsion", "[array]", etl::uint8_t, etl::int8_t, etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t, float,
                   double, long double)
{
  SECTION("not equal")
  {
    etl::array<TestType, 3> lhs {TestType {1}, TestType {2}, TestType {3}};
    etl::array<TestType, 3> rhs {TestType {7}, TestType {8}, TestType {9}};

    CHECK_FALSE(lhs == rhs);
    CHECK(lhs != rhs);
    CHECK(lhs < rhs);
    CHECK(lhs <= rhs);
    CHECK_FALSE(lhs > rhs);
    CHECK_FALSE(lhs >= rhs);
  }

  SECTION("equal")
  {
    etl::array<TestType, 3> lhs {TestType {1}, TestType {2}, TestType {3}};
    etl::array<TestType, 3> rhs {TestType {1}, TestType {2}, TestType {3}};

    CHECK(lhs == rhs);
    CHECK_FALSE(lhs != rhs);
    CHECK_FALSE(lhs < rhs);
    CHECK(lhs <= rhs);
    CHECK_FALSE(lhs > rhs);
    CHECK(lhs >= rhs);
  }
}

TEMPLATE_TEST_CASE("array: tuple_size", "[array]", etl::uint8_t, etl::int8_t, etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t, float,
                   double, long double)
{
  STATIC_REQUIRE(etl::tuple_size<etl::array<TestType, 1>>::value == 1);

  STATIC_REQUIRE(etl::tuple_size_v<etl::array<TestType, 2>> == 2);
  STATIC_REQUIRE(etl::tuple_size_v<etl::array<TestType, 3>> == 3);

  auto arr4 = etl::array {TestType(1), TestType(2), TestType(3), TestType(4)};
  STATIC_REQUIRE(etl::tuple_size_v<decltype(arr4)> == 4);

  auto arr5 = etl::array {1, 2, 3, 4, 5};
  STATIC_REQUIRE(etl::tuple_size_v<decltype(arr5)> == 5);
}

TEMPLATE_TEST_CASE("array: tuple_element", "[array]", etl::uint8_t, etl::int8_t, etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t, float,
                   double, long double)
{
  STATIC_REQUIRE(
    etl::is_same_v<typename etl::tuple_element<1, etl::array<TestType, 2>>::type, TestType>);
}

TEMPLATE_TEST_CASE("array: get", "[array]", etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)
{
  auto a = etl::array<TestType, 3> {};

  etl::get<0>(a) = TestType {1};
  etl::get<1>(a) = TestType {2};
  etl::get<2>(a) = TestType {3};

  REQUIRE(etl::get<0>(a) == TestType {1});
  REQUIRE(etl::get<1>(a) == TestType {2});
  REQUIRE(etl::get<2>(a) == TestType {3});
}

TEMPLATE_TEST_CASE("array: to_array", "[array]", etl::uint8_t, etl::int8_t, etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t, float,
                   double, long double)
{
  SECTION("cppreference.com example")
  {
    // copies a string literal
    auto a1 = etl::to_array("foo");
    STATIC_REQUIRE(a1.size() == 4);

    // deduces both element type and length
    auto a2 = etl::to_array({0, 2, 1, 3});
    STATIC_REQUIRE(etl::is_same_v<decltype(a2), etl::array<int, 4>>);

    // deduces length with element type specified
    // implicit conversion happens
    auto a3 = etl::to_array<TestType>({0, 1, 3});
    STATIC_REQUIRE(etl::is_same_v<decltype(a3), etl::array<TestType, 3>>);

    auto a4 = etl::to_array<etl::pair<TestType, float>>({
      {TestType {3}, 0.0F},
      {TestType {4}, 0.1F},
      {TestType {4}, 0.1e23F},
    });
    STATIC_REQUIRE(a4.size() == 3);

    struct non_copy
    {
      TestType val;

      non_copy(TestType init) : val {init} { }
      non_copy(non_copy&&) noexcept = default;
      non_copy(non_copy const&)     = delete;
      auto operator=(non_copy&&) noexcept -> non_copy& = default;
      auto operator=(non_copy const&) -> non_copy& = delete;
    };

    // creates a non-copyable etl::array
    auto a5 = etl::to_array({non_copy(TestType {42})});
    STATIC_REQUIRE(a5.size() == 1);

    // error: copying multidimensional arrays is not supported
    //    char s[2][6] = {"nice", "thing"};
    //    auto a6      = etl::to_array(s);
  }
}
