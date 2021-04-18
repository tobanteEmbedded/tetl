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
#include "etl/map.hpp"

#include "etl/warning.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEMPLATE_TEST_CASE("map: construct", "[map]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
  etl::map<TestType, TestType, 4> test {};

  auto func = [](etl::map_view<TestType, TestType> const& m) {
    REQUIRE(m.empty() == true);
    REQUIRE(m.size() == 0);
    REQUIRE(m.max_size() == 4);
    REQUIRE(m.find(TestType {1}) == nullptr);
    REQUIRE(m.count(TestType {1}) == 0);

    // there should be no elements
    for (auto const& item : m)
    {
      etl::ignore_unused(item);
      REQUIRE(false);
    }
  };

  func(test);
}

TEMPLATE_TEST_CASE("map: copy construct", "[map]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
  auto original = etl::map<TestType, TestType, 4> {};
  original.emplace(TestType {1}, TestType {42});
  auto copy = etl::map<TestType, TestType, 4> {original};

  REQUIRE(copy.size() == 1);
  REQUIRE(original.size() == copy.size());
  REQUIRE(copy.at(TestType {1}) == 42);
}

TEMPLATE_TEST_CASE("map: move construct", "[map]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
  auto original = etl::map<TestType, TestType, 4> {};
  original.emplace(TestType {1}, TestType {42});
  auto moved {etl::move(original)};

  REQUIRE(moved.size() == 1);
  REQUIRE(moved.at(TestType {1}) == 42);

  // NOLINTNEXTLINE(clang-analyzer-cplusplus.Move)
  REQUIRE(original.size() == 0);
}

TEMPLATE_TEST_CASE("map: operator=", "[map]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
  SECTION("Copy")
  {
    auto original = etl::map<TestType, TestType, 4> {};
    original.emplace(TestType {1}, TestType {42});
    auto copy = etl::map<TestType, TestType, 4> {};
    copy      = original;

    REQUIRE(copy.size() == 1);
    REQUIRE(original.size() == 1);
    REQUIRE(copy.at(TestType {1}) == 42);
  }

  SECTION("Move")
  {
    auto original = etl::map<TestType, TestType, 4> {};
    original.emplace(TestType {1}, TestType {42});
    auto moved = etl::map<TestType, TestType, 4> {};
    moved      = etl::map<TestType, TestType, 4> {etl::move(original)};

    REQUIRE(moved.size() == 1);
    REQUIRE(moved.at(TestType {1}) == 42);

    // NOLINTNEXTLINE(clang-analyzer-cplusplus.Move)
    REQUIRE(original.size() == 0);
  }
}

TEMPLATE_TEST_CASE("map: destruct", "[map]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
  struct Value
  {
    Value(int& ctor, int& d) : dtor {&d} { ctor++; }
    ~Value() { (*dtor)++; }

    int* dtor;
  };

  SECTION("emplace")
  {
    auto numCtors = 0;
    auto numDtors = 0;

    auto map = etl::map<TestType, Value, 4> {};
    map.emplace(TestType {1}, Value {numCtors, numDtors});
    map.emplace(TestType {2}, Value {numCtors, numDtors});
    map.emplace(TestType {3}, Value {numCtors, numDtors});
    map.emplace(TestType {4}, Value {numCtors, numDtors});
    REQUIRE(map.size() == 4);

    REQUIRE(numCtors == 4);
    // 4 * (1 final destruction)
    REQUIRE(numDtors == 4);
  }

  SECTION("emplace(make_pair())")
  {
    auto numCtors = 0;
    auto numDtors = 0;

    auto map = etl::map<TestType, Value, 4> {};
    map.emplace(etl::make_pair(TestType {1}, Value {numCtors, numDtors}));
    map.emplace(etl::make_pair(TestType {2}, Value {numCtors, numDtors}));
    map.emplace(etl::make_pair(TestType {3}, Value {numCtors, numDtors}));
    map.emplace(etl::make_pair(TestType {4}, Value {numCtors, numDtors}));
    REQUIRE(map.size() == 4);

    REQUIRE(numCtors == 4);
    // 4 * (1 move + 1 final destruction)
    REQUIRE(numDtors == 4 * 2);
  }
}

TEMPLATE_TEST_CASE("map: at", "[map]", etl::uint8_t, etl::int8_t, etl::uint16_t,
                   etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
                   etl::int64_t, float, double, long double)
{
  auto map = etl::map<TestType, TestType, 4> {};
  map.insert({TestType {1}, TestType {125}});
  map.insert({TestType {2}, TestType {42}});
  REQUIRE(map.at(1) == 125);
  REQUIRE(map.at(2) == 42);

  auto const map2 = map;
  REQUIRE(map2.at(1) == 125);
  REQUIRE(map2.at(2) == 42);
}

TEMPLATE_TEST_CASE("map: operator[]", "[map]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
  auto map = etl::map<int, TestType, 4> {};
  map.insert({1, TestType {125}});
  map.insert({2, TestType {42}});
  REQUIRE(map[1] == TestType {125});
  REQUIRE(map[2] == TestType {42});
  REQUIRE(map.contains(1) == true);
  REQUIRE(map.contains(2) == true);
  REQUIRE(map.contains(3) == false);
  REQUIRE(map[3] == 0);
  REQUIRE(map.contains(3) == true);
}

TEMPLATE_TEST_CASE("map: begin/cbegin", "[map]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
  auto m = etl::map<TestType, TestType, 4> {};
  m.insert({TestType {1}, TestType {125}});
  REQUIRE(m.begin() == m.cbegin());
  REQUIRE(m.begin()->second == 125);
}

TEMPLATE_TEST_CASE("map: end/cend", "[map]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
  auto m = etl::map<TestType, TestType, 4> {};
  m.insert({TestType {1}, TestType {125}});
  REQUIRE(m.end() == m.cend());
}

TEST_CASE("map: ranged-based-for", "[map]")
{
  WHEN("mutable")
  {
    auto m = etl::map<int, int, 4> {};
    m.insert({1, 125});
    m.insert({2, 125});
    m.insert({3, 125});

    auto result = 0;
    for (auto const& item : m) { result += item.second; }

    REQUIRE(result == 125 * 3);
  }
}

TEMPLATE_TEST_CASE("map: empty", "[map]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
  auto map = etl::map<int, TestType, 4> {};
  REQUIRE(map.empty() == true);
  map.insert({1, TestType {125}});
  REQUIRE(map.empty() == false);
}

TEMPLATE_TEST_CASE("map: size", "[map]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
  auto map = etl::map<int, TestType, 4> {};
  REQUIRE(map.size() == 0);
  map.insert({1, TestType {100}});
  REQUIRE(map.size() == 1);
  map.insert({2, TestType {100}});
  REQUIRE(map.size() == 2);
  map.insert({3, TestType {100}});
  REQUIRE(map.size() == 3);
}

TEMPLATE_TEST_CASE("map: count/contains", "[map]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
  auto map = etl::map<int, TestType, 4> {};
  map.insert({1, TestType {125}});
  map.insert({2, TestType {125}});
  map.insert({3, TestType {125}});
  REQUIRE(map.contains(1) == true);
  REQUIRE(map.count(1) == 1);
  REQUIRE(map.contains(3) == true);
  REQUIRE(map.count(3) == 1);
  REQUIRE(map.contains(42) == false);
  REQUIRE(map.count(42) == 0);
}

TEMPLATE_TEST_CASE("map: clear", "[map]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
  auto map = etl::map<int, TestType, 4> {};
  map.insert({1, TestType {100}});
  map.insert({2, TestType {100}});
  map.insert({3, TestType {100}});
  REQUIRE(map.empty() == false);
  REQUIRE(map.size() == 3);
  REQUIRE(map.count(1) == 1);

  map.clear();
  REQUIRE(map.empty() == true);
  REQUIRE(map.size() == 0);
  REQUIRE(map.count(1) == 0);
}

TEMPLATE_TEST_CASE("map: insert(value_type const&)", "[map]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)
{
  auto map  = etl::map<int, TestType, 4> {};
  auto pair = etl::pair<int, TestType> {1, TestType {100}};
  auto func = [&](auto const& p) {
    map.insert(p);
    REQUIRE(map.size() == 1);
    REQUIRE(map.count(1) == 1);
    REQUIRE(map.find(1)->second == 100);
  };

  func(pair);
}

TEMPLATE_TEST_CASE("map: insert(value_type &&)", "[map]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)
{
  auto map = etl::map<int, TestType, 4> {};

  map.insert(etl::pair<int, TestType> {2, TestType {125}});
  REQUIRE(map.size() == 1);
  REQUIRE(map.count(2) == 1);
  REQUIRE(map.find(2)->second == TestType {125});

  map.insert(etl::pair<int, TestType> {3, TestType {42}});
  REQUIRE(map.size() == 2);
  REQUIRE(map.count(3) == 1);
  REQUIRE(map.find(3)->second == TestType {42});

  map.insert(etl::pair<short, TestType> {14, TestType {100}});
  REQUIRE(map.size() == 3);
  REQUIRE(map.count(14) == 1);
  REQUIRE(map.find(14)->second == TestType {100});
}

TEMPLATE_TEST_CASE("map: emplace()", "[map]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
  auto map = etl::map<int, TestType, 4> {};
  REQUIRE(map.size() == 0);

  auto func = [&](auto& view) {
    auto res1 = view.emplace(1, TestType {100});
    REQUIRE(res1.second == true);
    REQUIRE(view.size() == 1);
    REQUIRE(view.count(1) == 1);
    REQUIRE(view.find(1)->second == 100);

    // emplacing the same key again should not override the original value.
    auto res2 = view.emplace(1, TestType {42});
    REQUIRE(res2.second == false);
    REQUIRE(view.size() == 1);
    REQUIRE(view.count(1) == 1);
    REQUIRE(view.find(1)->second == 100);
  };
  func(map);
  REQUIRE(map.size() == 1);
}

TEMPLATE_TEST_CASE("map: static_map<int, TestType>", "[map]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)
{
  etl::static_map<int, TestType, 16> map {};
  REQUIRE(map.empty());
  REQUIRE(map.size() == 0);  // NOLINT
  REQUIRE(map.max_size() == 16);
  REQUIRE(map.begin() == map.end());
  REQUIRE(map.rbegin() == map.rend());
  REQUIRE(etl::as_const(map).begin() == etl::as_const(map).end());
  REQUIRE(etl::as_const(map).rbegin() == etl::as_const(map).rend());

  auto res = map.emplace(143, TestType {1});
  REQUIRE(map.size() == 1);
  REQUIRE(map.max_size() == 16);
  REQUIRE_FALSE(map.empty());
  REQUIRE(map.begin() != map.end());
  REQUIRE(map.rbegin() != map.rend());
  REQUIRE(etl::as_const(map).begin() != etl::as_const(map).end());
  REQUIRE(etl::as_const(map).rbegin() != etl::as_const(map).rend());
  REQUIRE(res.second);
  //  REQUIRE(res.first->first == 143);
  //  REQUIRE(res.first->second == TestType {1});

  auto p    = etl::make_pair(42, TestType {2});
  auto ires = map.insert(p);
  REQUIRE(ires.second);
  REQUIRE(map.size() == 2);
  //  REQUIRE(ires.first->first == 42);
  //  REQUIRE(ires.first->second == TestType {2});

  auto ires2 = map.insert(etl::pair<long, TestType>(10, TestType {2}));
  REQUIRE(ires2.second);
  REQUIRE(map.size() == 3);
  //  REQUIRE(ires2.first->first == 10);
  //  REQUIRE(ires2.first->second == TestType {2});

  auto range = etl::array {
    etl::pair<int, TestType> {1, TestType {1}},
    etl::pair<int, TestType> {2, TestType {2}},
    etl::pair<int, TestType> {3, TestType {3}},
  };
  map.insert(range.begin(), range.end());
  REQUIRE(map.size() == 6);
  //  REQUIRE(etl::next(map.begin(), 5)->first == 3);
}
