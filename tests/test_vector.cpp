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

#include "etl/vector.hpp"

#include "etl/numeric.hpp"

TEMPLATE_TEST_CASE("vector/static_vector: typedefs", "[vector]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)
{
  using vector_t = etl::static_vector<TestType, 16>;

  STATIC_REQUIRE(etl::is_same_v<TestType, typename vector_t::value_type>);
  STATIC_REQUIRE(etl::is_same_v<TestType&, typename vector_t::reference>);
  STATIC_REQUIRE(
    etl::is_same_v<TestType const&, typename vector_t::const_reference>);
  STATIC_REQUIRE(etl::is_same_v<TestType*, typename vector_t::pointer>);
  STATIC_REQUIRE(
    etl::is_same_v<TestType const*, typename vector_t::const_pointer>);
  STATIC_REQUIRE(etl::is_same_v<TestType*, typename vector_t::iterator>);
  STATIC_REQUIRE(
    etl::is_same_v<TestType const*, typename vector_t::const_iterator>);
}

TEMPLATE_TEST_CASE("vector/static_vector: zero sized", "[vector]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)
{
  auto zero = etl::static_vector<TestType, 0> {};
  CHECK(zero.capacity() == zero.max_size());
  CHECK(zero.empty());
  CHECK(zero.size() == 0);
  CHECK(zero.capacity() == 0);
  CHECK(zero.data() == nullptr);
  CHECK(zero.full());
}

TEMPLATE_TEST_CASE("vector/static_vector: ctor empty", "[vector]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)
{
  etl::static_vector<TestType, 16> lhs {};
  CHECK(lhs.empty());
  CHECK(lhs.size() == 0);
  CHECK_FALSE(lhs.full());

  CHECK(etl::begin(lhs) == etl::end(lhs));
  CHECK(etl::cbegin(lhs) == etl::cend(lhs));
  CHECK(etl::begin(etl::as_const(lhs)) == etl::end(etl::as_const(lhs)));

  etl::static_vector<TestType, 16> rhs {};
  CHECK(rhs.empty());
  CHECK(rhs.size() == 0);
  CHECK_FALSE(rhs.full());

  // comparison empty
  CHECK(lhs == rhs);
  CHECK(rhs == lhs);
  CHECK_FALSE(lhs != rhs);
  CHECK_FALSE(rhs != lhs);
}

TEMPLATE_TEST_CASE("vector/static_vector: ctor begin/end", "[vector]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
  auto first = etl::static_vector<TestType, 4>(4);
  auto second
    = etl::static_vector<TestType, 4> {etl::begin(first), etl::end(first)};
  CHECK(first == second);
}

TEMPLATE_TEST_CASE("vector/static_vector: ctor size", "[vector]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)
{
  etl::static_vector<TestType, 16> vec(8);
  CHECK(vec.size() == 8);
  CHECK(etl::all_of(begin(vec), end(vec),
                    [](auto val) { return val == TestType(); }));
}

TEMPLATE_TEST_CASE("vector/static_vector: ctor size,value", "[vector]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
  using T = TestType;
  etl::static_vector<T, 16> vec(16, T(42));
  CHECK(vec.size() == 16);
  CHECK(
    etl::all_of(begin(vec), end(vec), [](auto val) { return val == T(42); }));
}

TEMPLATE_TEST_CASE("vector/static_vector: ctor copy", "[vector]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)
{
  auto first = etl::static_vector<TestType, 4>(4);
  etl::static_vector<TestType, 4> const& second {first};
  CHECK(first == second);
}

TEMPLATE_TEST_CASE("vector/static_vector: ctor move", "[vector]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)
{
  auto first = etl::static_vector<TestType, 4>(4);
  etl::static_vector<TestType, 4> copy {etl::move(first)};

  auto cmp = [](auto val) { return val == TestType(0); };
  CHECK(etl::all_of(begin(copy), end(copy), cmp));
}

TEMPLATE_TEST_CASE("vector/static_vector: assignment copy", "[vector]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
  auto first = etl::static_vector<TestType, 4>(4);
  etl::static_vector<TestType, 4> copy {};
  copy = first;
  CHECK(first == copy);
}

TEMPLATE_TEST_CASE("vector/static_vector: assignment move", "[vector]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
  auto first = etl::static_vector<TestType, 4>(4);
  etl::static_vector<TestType, 4> copy {};
  copy = etl::move(first);

  auto cmp = [](auto val) { return val == TestType(0); };
  CHECK(etl::all_of(begin(copy), end(copy), cmp));
}

TEMPLATE_TEST_CASE("vector/static_vector: begin/end", "[vector]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)
{
  etl::static_vector<TestType, 16> vec {};
  CHECK(vec.empty());
  CHECK(etl::begin(vec) == etl::end(vec));
  CHECK(etl::cbegin(vec) == etl::cend(vec));
  CHECK(etl::begin(etl::as_const(vec)) == etl::end(etl::as_const(vec)));

  vec.push_back(TestType {2});
  CHECK_FALSE(etl::begin(vec) == etl::end(vec));
  CHECK_FALSE(etl::cbegin(vec) == etl::cend(vec));
  CHECK_FALSE(etl::begin(etl::as_const(vec)) == etl::end(etl::as_const(vec)));
}

TEMPLATE_TEST_CASE("vector/static_vector: rbegin/rend", "[vector]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
  etl::static_vector<TestType, 16> vec {};
  CHECK(vec.empty());
  CHECK(etl::rbegin(vec) == etl::rend(vec));
  CHECK(etl::crbegin(vec) == etl::crend(vec));
  CHECK(etl::rbegin(etl::as_const(vec)) == etl::rend(etl::as_const(vec)));

  vec.push_back(TestType {2});
  CHECK(*etl::rbegin(vec) == TestType {2});
  CHECK_FALSE(etl::rbegin(vec) == etl::rend(vec));
  CHECK_FALSE(etl::crbegin(vec) == etl::crend(vec));
  CHECK_FALSE(etl::rbegin(etl::as_const(vec)) == etl::rend(etl::as_const(vec)));

  vec.push_back(TestType {3});
  CHECK(*etl::rbegin(vec) == TestType {3});
}

TEMPLATE_TEST_CASE("vector/static_vector: resize", "[vector]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)
{
  auto vec = etl::static_vector<TestType, 4> {};
  CHECK(vec.size() == 0);

  // grow
  vec.resize(etl::size_t {2});
  CHECK(vec.size() == 2);
  CHECK(
    etl::all_of(begin(vec), end(vec), [](auto x) { return x == TestType(); }));

  // grow full capacity
  vec.resize(etl::size_t {4});
  CHECK(vec.size() == 4);
  CHECK(
    etl::all_of(begin(vec), end(vec), [](auto x) { return x == TestType(); }));

  // same size
  vec.resize(etl::size_t {4});
  CHECK(vec.size() == 4);
  CHECK(
    etl::all_of(begin(vec), end(vec), [](auto x) { return x == TestType(); }));

  // shrink
  vec.resize(etl::size_t {2});
  CHECK(vec.size() == 2);
}

TEMPLATE_TEST_CASE("vector/static_vector: assign", "[vector]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)
{
  auto a = etl::static_vector<TestType, 4> {};
  a.assign(4, TestType {42});
  CHECK(a.size() == 4);
  CHECK(a.front() == 42);
  CHECK(a.back() == 42);
  CHECK(etl::as_const(a).size() == 4);
  CHECK(etl::as_const(a).front() == 42);
  CHECK(etl::as_const(a).back() == 42);
  CHECK(etl::all_of(begin(a), end(a),
                    [](auto val) { return val == TestType(42); }));

  auto b = etl::static_vector<TestType, 4> {4};
  b.assign(a.begin(), a.end());
  CHECK(b.size() == 4);
  CHECK(b.front() == 42);
  CHECK(b.back() == 42);
  CHECK(etl::all_of(begin(b), end(b),
                    [](auto val) { return val == TestType(42); }));
}

TEMPLATE_TEST_CASE("vector/static_vector: pop_back", "[vector]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)
{
  auto vec = etl::static_vector<TestType, 4> {};
  CHECK(vec.size() == 0);
  vec.push_back(TestType(1));
  CHECK(vec.size() == 1);
  vec.pop_back();
  CHECK(vec.size() == 0);
}

TEMPLATE_TEST_CASE("vector/static_vector: push_back", "[vector]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)
{
  etl::static_vector<TestType, 16> vec {};
  CHECK(vec.empty());

  vec.push_back(TestType {1});
  CHECK_FALSE(vec.empty());
  CHECK(vec.front() == TestType {1});
  CHECK(vec.back() == TestType {1});

  vec.push_back(TestType {2});
  CHECK_FALSE(vec.empty());
  CHECK(vec.front() == TestType {1});
  CHECK(vec.back() == TestType {2});

  CHECK_FALSE(etl::begin(vec) == etl::end(vec));
  CHECK_FALSE(etl::cbegin(vec) == etl::cend(vec));
  CHECK_FALSE(etl::begin(etl::as_const(vec)) == etl::end(etl::as_const(vec)));
}

TEMPLATE_TEST_CASE("vector/static_vector: erase", "[vector]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)
{
  auto vec = etl::static_vector<TestType, 4> {4};
  etl::generate(etl::begin(vec), etl::end(vec), [] {
    static auto val = TestType {};
    return val += TestType(1);
  });

  CHECK(vec.front() == TestType(1));
  vec.erase(vec.begin());
  CHECK(vec.front() == TestType(2));
}

TEMPLATE_TEST_CASE("vector/static_vector: swap", "[vector]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)
{
  SECTION("method")
  {
    auto lhs       = etl::static_vector<TestType, 4> {4};
    auto generator = [] {
      static auto val = TestType {};
      return val += TestType(1);
    };

    etl::generate(etl::begin(lhs), etl::end(lhs), generator);
    auto rhs = lhs;

    lhs.swap(rhs);
    CHECK(lhs == rhs);
    rhs.swap(lhs);
    CHECK(lhs == rhs);
  }

  SECTION("free function")
  {
    auto lhs       = etl::static_vector<TestType, 4> {4};
    auto generator = [] {
      static auto val = TestType {};
      return val += TestType(1);
    };

    etl::generate(etl::begin(lhs), etl::end(lhs), generator);
    auto rhs = lhs;

    using ::etl::swap;
    swap(lhs, rhs);
    CHECK(lhs == rhs);
    swap(rhs, lhs);
    CHECK(lhs == rhs);
  }
}

TEMPLATE_TEST_CASE("vector/static_vector: operator==/!=", "[vector]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
  SECTION("empty")
  {
    auto lhs_1       = etl::static_vector<TestType, 4> {};
    auto const rhs_1 = etl::static_vector<TestType, 4> {};
    CHECK(lhs_1 == rhs_1);
    CHECK_FALSE(lhs_1 != rhs_1);

    auto const lhs_2 = etl::static_vector<TestType, 4>();
    auto const rhs_2 = etl::static_vector<TestType, 4>(2);
    CHECK(lhs_2 != rhs_2);
    CHECK_FALSE(lhs_2 == rhs_2);

    auto const lhs_3 = etl::static_vector<TestType, 4>(2);
    auto const rhs_3 = etl::static_vector<TestType, 4>();
    CHECK(lhs_3 != rhs_3);
    CHECK_FALSE(lhs_3 == rhs_3);
  }

  SECTION("with elements")
  {
    auto lhs_1 = etl::static_vector<TestType, 4> {};
    lhs_1.push_back(TestType(1));
    lhs_1.push_back(TestType(2));
    auto rhs_1 = etl::static_vector<TestType, 4> {};
    rhs_1.push_back(TestType(1));
    rhs_1.push_back(TestType(2));

    CHECK(lhs_1 == rhs_1);
    CHECK_FALSE(lhs_1 != rhs_1);

    auto lhs_2 = etl::static_vector<TestType, 4> {};
    lhs_2.push_back(TestType(1));
    lhs_2.push_back(TestType(2));
    auto rhs_2 = etl::static_vector<TestType, 4> {};
    rhs_2.push_back(TestType(1));
    rhs_2.push_back(TestType(3));

    CHECK(lhs_2 != rhs_2);
    CHECK_FALSE(lhs_2 == rhs_2);
  }
}

TEMPLATE_TEST_CASE("vector/static_vector: operator</<=", "[vector]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t)
{
  SECTION("empty")
  {
    auto lhs       = etl::static_vector<TestType, 4>();
    auto const rhs = etl::static_vector<TestType, 4>();
    CHECK_FALSE(lhs < rhs);
    CHECK_FALSE(rhs < lhs);
    CHECK(lhs <= rhs);
    CHECK(rhs <= lhs);
  }

  SECTION("full")
  {
    auto lhs = etl::static_vector<TestType, 4>(4);
    etl::iota(begin(lhs), end(lhs), TestType(0));
    auto rhs = etl::static_vector<TestType, 4>(4);
    etl::iota(begin(rhs), end(rhs), TestType(1));

    CHECK(lhs < rhs);
    CHECK(lhs <= rhs);

    CHECK_FALSE(rhs < lhs);
    CHECK_FALSE(rhs <= lhs);
  }
}

TEMPLATE_TEST_CASE("vector/static_vector: operator>/>=", "[vector]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t)
{
  SECTION("empty")
  {
    auto lhs       = etl::static_vector<TestType, 4>();
    auto const rhs = etl::static_vector<TestType, 4>();
    CHECK_FALSE(lhs > rhs);
    CHECK_FALSE(rhs > lhs);
    CHECK(lhs >= rhs);
    CHECK(rhs >= lhs);
  }

  SECTION("full")
  {
    auto lhs = etl::static_vector<TestType, 4>(4);
    etl::iota(begin(lhs), end(lhs), TestType(1));
    auto rhs = etl::static_vector<TestType, 4>(4);
    etl::iota(begin(rhs), end(rhs), TestType(0));

    CHECK(lhs > rhs);
    CHECK(lhs >= rhs);

    CHECK_FALSE(rhs > lhs);
    CHECK_FALSE(rhs >= lhs);
  }
}

TEMPLATE_TEST_CASE("vector/static_vector: erase/erase_if", "[vector]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t)
{
  using T = TestType;

  SECTION("empty")
  {
    auto data = etl::static_vector<T, 4>();
    CHECK(data.empty());
    CHECK(etl::erase(data, TestType(0)) == 0);
    CHECK(data.empty());
  }

  SECTION("range")
  {
    auto data = etl::array {T(0), T(0), T(1), T(2), T(0), T(2)};
    auto vec  = etl::static_vector<T, 6>(begin(data), end(data));
    CHECK(vec.full());
    CHECK(etl::erase(vec, TestType(0)) == 3);
    CHECK_FALSE(vec.full());
    CHECK(vec.size() == 3);
  }
}

namespace
{
template <typename T>
struct Vertex
{
  T x;
  T y;
  T z;

  Vertex(T _x, T _y, T _z) : x {_x}, y {_y}, z {_z} { }
};

template <typename T>
[[nodiscard]] constexpr auto operator==(Vertex<T> const& lhs,
                                        Vertex<T> const& rhs) -> bool
{
  return (lhs.x == rhs.x) && (lhs.y == rhs.y) && (lhs.z == rhs.z);
}

template <typename T>
[[nodiscard]] constexpr auto operator!=(Vertex<T> const& lhs,
                                        Vertex<T> const& rhs) -> bool
{
  return !(lhs == rhs);
}

TEMPLATE_TEST_CASE("vector/static_vector: non_trivial zero", "[vector]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
  etl::static_vector<Vertex<TestType>, 0> zero {};
  CHECK(zero.empty());
  CHECK(zero.size() == 0);
  CHECK(zero.capacity() == 0);
  CHECK(zero.data() == nullptr);
  CHECK(zero.full());
}

TEMPLATE_TEST_CASE("vector/static_vector: non_trivial ctor empty", "[vector]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
  etl::static_vector<Vertex<TestType>, 16> lhs {};
  CHECK(lhs.empty());
  etl::static_vector<Vertex<TestType>, 16> rhs {};
  CHECK(rhs.empty());

  CHECK(etl::begin(lhs) == etl::end(lhs));
  CHECK(etl::cbegin(lhs) == etl::cend(lhs));
  CHECK(etl::begin(etl::as_const(lhs)) == etl::end(etl::as_const(lhs)));

  CHECK(lhs == rhs);
  CHECK(rhs == lhs);
  CHECK_FALSE(lhs != rhs);
  CHECK_FALSE(rhs != lhs);
}

TEMPLATE_TEST_CASE("vector/static_vector: non_trivial emplace_back", "[vector]",
                   char, int, float)
{
  etl::static_vector<Vertex<TestType>, 16> lhs {};
  CHECK(lhs.empty());
  etl::static_vector<Vertex<TestType>, 16> rhs {};
  CHECK(rhs.empty());

  rhs.emplace_back(TestType(1.20F), TestType(1.00F), TestType(1.43F));
  CHECK_FALSE(rhs.empty());
  CHECK_FALSE(rhs == lhs);
  CHECK(rhs.size() == 1);

  lhs.emplace_back(TestType(1.20F), TestType(1.00F), TestType(1.43F));
  CHECK_FALSE(lhs.empty());
  CHECK(rhs == lhs);
  CHECK(lhs.size() == 1);
}

TEMPLATE_TEST_CASE("vector/static_vector: non_trivial emplace", "[vector]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
  etl::static_vector<Vertex<TestType>, 3> vec {};
  vec.emplace(vec.end(), TestType(1.20F), TestType(1.00F), TestType(1.43F));
  CHECK_FALSE(vec.empty());
  CHECK(vec.size() == 1);
}

TEMPLATE_TEST_CASE("vector/static_vector: non_trivial pop_back", "[vector]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
  etl::static_vector<Vertex<TestType>, 3> original {};
  auto vertex = Vertex {TestType(1), TestType(2), TestType(3)};
  original.push_back(vertex);
  CHECK(original.size() == 1);
  CHECK(original.front() == vertex);
  CHECK(original.back() == vertex);
  CHECK(etl::as_const(original).front() == vertex);
  CHECK(etl::as_const(original).back() == vertex);

  original.pop_back();
  CHECK(original.size() == 0);
}

TEMPLATE_TEST_CASE("vector/static_vector: non_trivial insert(copy)", "[vector]",
                   char, int, float)
{
  auto vec = etl::static_vector<Vertex<TestType>, 3> {};
  CHECK(vec.size() == 0);
  auto vertex = Vertex {TestType(1.20F), TestType(1.00F), TestType(1.43F)};
  vec.insert(vec.begin(), vertex);
  vec.insert(vec.begin(), vertex);
  CHECK(vec.size() == 2);
}

TEMPLATE_TEST_CASE("vector/static_vector: non_trivial insert(move)", "[vector]",
                   char, int, float)
{
  auto vec = etl::static_vector<Vertex<TestType>, 3> {};
  CHECK(vec.size() == 0);
  vec.insert(vec.begin(),
             Vertex {TestType(1.20F), TestType(1.00F), TestType(1.43F)});
  vec.insert(vec.begin(),
             Vertex {TestType(1.20F), TestType(1.00F), TestType(1.43F)});
  CHECK(vec.size() == 2);
}

TEMPLATE_TEST_CASE("vector/static_vector: non_trivial operator[]", "[vector]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
  auto a   = Vertex {TestType(1), TestType(1), TestType(1)};
  auto b   = Vertex {TestType(2), TestType(2), TestType(2)};
  auto vec = etl::static_vector<Vertex<TestType>, 3> {};
  CHECK(vec.size() == 0);

  vec.insert(vec.begin(), a);
  vec.insert(vec.begin(), b);
  CHECK(vec[0] == b);
  CHECK(etl::as_const(vec)[1] == a);
}

}  // namespace
