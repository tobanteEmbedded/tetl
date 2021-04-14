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
#include "etl/span.hpp"

#include "etl/iterator.hpp"
#include "etl/vector.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEMPLATE_TEST_CASE("span: deduction guides", "[span]", char, int, float)
{
  SECTION("from C array")
  {
    TestType arr[16] = {};
    auto sp          = etl::span {arr};
    REQUIRE(sp.data() == &arr[0]);
    REQUIRE(sp.size() == 16);
  }

  SECTION("from etl::array")
  {
    auto arr = etl::array<TestType, 8> {};
    auto sp  = etl::span {arr};
    REQUIRE(sp.data() == arr.data());
    REQUIRE(sp.size() == 8);
  }

  SECTION("from etl::array const")
  {
    auto const arr = etl::array<TestType, 8> {};
    auto const sp  = etl::span {arr};
    REQUIRE(sp.data() == arr.data());
    REQUIRE(sp.size() == 8);
  }

  SECTION("from Container")
  {
    auto vec = etl::static_vector<TestType, 8> {};
    vec.push_back(TestType {});
    vec.push_back(TestType {});
    auto sp = etl::span {vec};
    REQUIRE(sp.data() == vec.data());
    REQUIRE(sp.size() == 2);
  }

  SECTION("from Container const")
  {
    auto const vec = []()
    {
      auto v = etl::static_vector<TestType, 8> {};
      v.push_back(TestType {});
      v.push_back(TestType {});
      return v;
    }();

    auto const sp = etl::span {vec};
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
    auto sp  = etl::span<TestType, 8> {etl::begin(arr), etl::size(arr)};
    REQUIRE_FALSE(sp.empty());
    REQUIRE(sp.data() == arr.data());
    REQUIRE(sp.size() == arr.size());
    REQUIRE(sp.extent == arr.size());
  }

  SECTION("static array")
  {
    auto arr = etl::array<TestType, 8> {};
    auto sp  = etl::span<TestType> {etl::begin(arr), etl::size(arr)};
    REQUIRE_FALSE(sp.empty());
    REQUIRE(sp.data() == arr.data());
    REQUIRE(sp.size() == arr.size());
    REQUIRE(sp.extent == etl::dynamic_extent);
  }

  SECTION("static vector")
  {
    auto vec = etl::static_vector<TestType, 8> {};
    auto rng = []() { return TestType {42}; };
    etl::generate_n(etl::back_inserter(vec), 4, rng);

    auto sp = etl::span<TestType> {etl::begin(vec), etl::size(vec)};
    REQUIRE_FALSE(sp.empty());
    REQUIRE(sp.data() == vec.data());
    REQUIRE(sp.size() == vec.size());
    REQUIRE(sp.extent == etl::dynamic_extent);
    REQUIRE(etl::all_of(etl::begin(sp), etl::end(sp),
                        [](auto& x) { return x == TestType {42}; }));
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
    auto sp   = etl::span<TestType> {etl::begin(data), etl::size(data)};
    REQUIRE_FALSE(sp.begin() == sp.end());
    REQUIRE_FALSE(etl::begin(sp) == etl::end(sp));

    auto counter = 0;
    for (auto const& x : sp)
    {
      etl::ignore_unused(x);
      counter++;
    }
    REQUIRE(counter == 4);
  }

  SECTION("algorithm")
  {
    auto data = etl::array<TestType, 4> {};
    auto sp   = etl::span<TestType> {etl::begin(data), etl::size(data)};
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
  auto rng = []()
  {
    static auto i = TestType {127};
    return TestType {i--};
  };

  auto vec = etl::static_vector<TestType, 8> {};
  etl::generate_n(etl::back_inserter(vec), 4, rng);
  auto sp = etl::span<TestType> {etl::begin(vec), etl::size(vec)};
  REQUIRE(sp[0] == TestType {127});
  REQUIRE(sp[1] == TestType {126});
  REQUIRE(sp[2] == TestType {125});
  REQUIRE(sp[3] == TestType {124});

  auto const csp = etl::span {sp};
  REQUIRE(csp[0] == TestType {127});
  REQUIRE(csp[1] == TestType {126});
  REQUIRE(csp[2] == TestType {125});
  REQUIRE(csp[3] == TestType {124});
}

TEMPLATE_TEST_CASE("span: size_bytes", "[span]", char, int, float, double,
                   etl::uint64_t)
{
  auto vec = etl::static_vector<TestType, 6> {};
  etl::generate_n(etl::back_inserter(vec), 4, []() { return TestType {42}; });
  auto sp = etl::span<TestType> {etl::begin(vec), etl::size(vec)};

  REQUIRE(sp.size_bytes() == 4 * sizeof(TestType));
}