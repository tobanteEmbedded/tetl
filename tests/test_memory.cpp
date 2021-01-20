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

#include "catch2/catch.hpp"

#include "etl/array.hpp"
#include "etl/cstddef.hpp"
#include "etl/memory.hpp"

TEMPLATE_TEST_CASE("memory/small_ptr: sizeof", "[memory]", uint8_t, uint16_t,
                   uint32_t, uint64_t)
{
  using int_ptr_t = etl::small_ptr<int, 0, TestType>;
  STATIC_REQUIRE(sizeof(int_ptr_t) == sizeof(TestType));

  using float_ptr_t = etl::small_ptr<float, 0, TestType>;
  STATIC_REQUIRE(sizeof(float_ptr_t) == sizeof(TestType));
}

TEMPLATE_TEST_CASE("memory/small_ptr: construct()", "[memory]", int, float,
                   long)
{
  using ptr_t = etl::small_ptr<TestType, 0, uintptr_t>;
  auto ptr    = ptr_t {};
  etl::ignore_unused(ptr);
  REQUIRE(true);
}

TEMPLATE_TEST_CASE("memory/small_ptr: construct(nullptr)", "[memory]", int,
                   float, long)
{
  using ptr_t = etl::small_ptr<TestType, 0, uintptr_t>;
  REQUIRE(ptr_t {nullptr}.compressed_value() == 0U);
}

TEMPLATE_TEST_CASE("memory/small_ptr: offset", "[memory]", int, float, long)
{
  using namespace Catch::Generators;
  using ptr_t = etl::small_ptr<TestType const, 16, uintptr_t>;
  auto [addr] = GENERATE(table<int>({
    {32},
    {2048},
    {4100},
  }));
  auto ptr    = ptr_t {reinterpret_cast<TestType*>(addr)};
  REQUIRE(ptr.compressed_value() == static_cast<uintptr_t>(addr - 16));
  REQUIRE(reinterpret_cast<uintptr_t>(ptr.operator->())
          == static_cast<uintptr_t>(addr));
}

TEMPLATE_TEST_CASE("memory/small_ptr: get", "[memory]", int, float, long)
{
  using ptr_t = etl::small_ptr<TestType const, 0, uintptr_t>;

  WHEN("mutable")
  {
    auto val = TestType(1.43);
    auto ptr = ptr_t {&val};
    REQUIRE(ptr.get() == &val);
  }

  WHEN("const")
  {
    auto const val = TestType(1.43);
    auto const ptr = ptr_t {&val};
    REQUIRE(ptr.get() == &val);
  }
}

TEMPLATE_TEST_CASE("memory/small_ptr: operator*", "[memory]", int, float, long)
{
  WHEN("mutable")
  {
    using ptr_t = etl::small_ptr<TestType, 0, uintptr_t>;
    auto val    = TestType(1.43);
    auto ptr    = ptr_t {&val};
    REQUIRE(*ptr == val);
  }

  WHEN("const")
  {
    using ptr_t    = etl::small_ptr<TestType const, 0, uintptr_t>;
    auto const val = TestType(1.43);
    auto const ptr = ptr_t {&val};
    REQUIRE(*ptr == val);
  }
}

TEMPLATE_TEST_CASE("memory/small_ptr: operator Type*", "[memory]", int, float,
                   long)
{
  using ptr_t = etl::small_ptr<TestType, 0, uintptr_t>;

  auto val  = TestType(1.43);
  auto ptr  = ptr_t {&val};
  auto func = [&val](TestType* p) { REQUIRE(*p == val); };
  func(ptr);
}

TEMPLATE_TEST_CASE("memory/small_ptr: operator Type const*", "[memory]", int,
                   float, long)
{
  using ptr_t = etl::small_ptr<TestType const, 0, uintptr_t>;

  auto const val = TestType(1.43);
  auto const ptr = ptr_t {&val};
  auto func      = [&val](TestType const* p) { REQUIRE(*p == val); };
  func(ptr);
}

TEMPLATE_TEST_CASE("memory/small_ptr: operator-", "[memory]", int, float, long)
{
  using ptr_t = etl::small_ptr<TestType const, 0, uintptr_t>;
  auto data   = etl::array<TestType, 4> {};
  REQUIRE(ptr_t {&data[1]} - ptr_t {&data[0]} == 1);
  REQUIRE(ptr_t {&data[2]} - ptr_t {&data[0]} == 2);
  REQUIRE(ptr_t {&data[3]} - ptr_t {&data[0]} == 3);
}

TEMPLATE_TEST_CASE("memory/small_ptr: operator--", "[memory]", int, float, long)
{
  using ptr_t = etl::small_ptr<TestType const, 0, uintptr_t>;

  WHEN("pre")
  {
    auto const data = etl::array<TestType, 4> {};
    auto ptr        = ptr_t {&data[1]};
    REQUIRE((--ptr).get() == ptr_t {&data[0]}.get());
  }

  WHEN("post")
  {
    auto const data = etl::array<TestType, 4> {};
    auto ptr        = ptr_t {&data[1]};
    REQUIRE((ptr--).get() == ptr_t {&data[1]}.get());
    REQUIRE(ptr.get() == ptr_t {&data[0]}.get());
  }
}

TEMPLATE_TEST_CASE("memory/small_ptr: operator++", "[memory]", int, float, long)
{
  using ptr_t = etl::small_ptr<TestType const, 0, uintptr_t>;

  WHEN("pre")
  {
    auto const data = etl::array<TestType, 4> {};
    auto ptr        = ptr_t {&data[1]};
    REQUIRE((++ptr).get() == ptr_t {&data[2]}.get());
  }

  WHEN("post")
  {
    auto const data = etl::array<TestType, 4> {};
    auto ptr        = ptr_t {&data[1]};
    REQUIRE((ptr++).get() == ptr_t {&data[1]}.get());
    REQUIRE(ptr.get() == ptr_t {&data[2]}.get());
  }
}

TEMPLATE_TEST_CASE("memory/ptr_with_int: ctor(default)", "[memory]", int, float,
                   long)
{
  using etl::uint32_t;
  using pointer_type = etl::ptr_with_int<TestType, 20, 12, uint32_t, uint32_t>;

  auto ptr = pointer_type();
  CHECK(ptr.get_ptr() == nullptr);
  CHECK(ptr.operator->() == nullptr);
  CHECK(ptr.get_int() == 0);

  auto const cptr = pointer_type();
  CHECK(cptr.get_ptr() == nullptr);
  CHECK(cptr.operator->() == nullptr);
  CHECK(cptr.get_int() == 0);
}

TEMPLATE_TEST_CASE("memory/ptr_with_int: ctor(pointer)", "[memory]", int, float,
                   long)
{
  using pointer_type = etl::ptr_with_int<TestType, 50, 14>;

  auto ptr = pointer_type((TestType*)((etl::uintptr_t)(143)));
  CHECK((etl::uintptr_t)(ptr.get_ptr()) == 143);
  CHECK(ptr.get_int() == 0);

  auto const cptr = pointer_type((TestType*)((etl::uintptr_t)(143)));
  CHECK((etl::uintptr_t)(cptr.get_ptr()) == 143);
  CHECK(cptr.get_int() == 0);
}

TEMPLATE_TEST_CASE("memory/ptr_with_int: ctor(pointer,integer)", "[memory]",
                   int, float, long)
{
  using pointer_type = etl::ptr_with_int<TestType, 48, 16>;

  auto ptr = pointer_type((TestType*)((etl::uintptr_t)(143)), 42);
  CHECK((etl::uintptr_t)(ptr.get_ptr()) == 143);
  CHECK(ptr.get_int() == 42);

  auto const cptr = pointer_type((TestType*)((etl::uintptr_t)(143)), 1000);
  CHECK((etl::uintptr_t)(cptr.get_ptr()) == 143);
  CHECK(cptr.get_int() == 1000);
}

TEMPLATE_TEST_CASE("memory/ptr_with_int: operator pointer", "[memory]", int,
                   float, long)
{
  using pointer_type = etl::ptr_with_int<TestType, 48, 16>;
  auto func = [](TestType* ptr) { CHECK((etl::uintptr_t)(ptr) == 143); };
  auto ptr  = pointer_type((TestType*)((etl::uintptr_t)(143)), 1000);
  CHECK(ptr.get_int() == 1000);
  func(ptr);
}

TEMPLATE_TEST_CASE("memory/ptr_with_int: operator const_pointer", "[memory]",
                   int, float, long)
{
  using pointer_type = etl::ptr_with_int<TestType, 48, 16>;
  auto func = [](TestType const* ptr) { CHECK((etl::uintptr_t)(ptr) == 143); };
  auto const ptr = pointer_type((TestType*)((etl::uintptr_t)(143)), 1000);
  CHECK(ptr.get_int() == 1000);
  func(ptr);
}

TEMPLATE_TEST_CASE("memory/ptr_with_int: operator*", "[memory]", int, float,
                   long)
{
  using pointer_type = etl::ptr_with_int<TestType, 64, 0>;
  auto val           = TestType {42};

  auto ptr = pointer_type(&val);
  CHECK(*ptr == TestType {42});

  auto const cptr = pointer_type(&val);
  CHECK(*cptr == TestType {42});
}

TEMPLATE_TEST_CASE("memory: addressof(object)", "[memory]", int, float, long)
{
  auto val = TestType(14.3);
  REQUIRE(etl::addressof(val) == &val);
}

TEMPLATE_TEST_CASE("memory: default_delete", "[memory]", int, float, long)
{
  SECTION("scalar")
  {
    auto deleter = etl::default_delete<TestType>();
    auto* ptr    = ::new TestType {};
    deleter(ptr);
  }

  SECTION("array")
  {
    auto deleter = etl::default_delete<TestType[]>();
    auto* ptr    = ::new TestType[512];
    deleter(ptr);
  }
  SUCCEED();
}

namespace
{
auto some_function() -> void { }
}  // namespace

TEST_CASE("memory: addressof(function)", "[memory]")
{
  REQUIRE(etl::addressof(some_function) == &some_function);
}

TEST_CASE("memory: destroy_at", "[memory]")
{
  struct Counter
  {
    int& value;
    Counter(int& v) : value(v) { }
    ~Counter() { value++; }
  };

  alignas(Counter) etl::byte buffer[sizeof(Counter) * 8];

  auto counter = 0;
  for (auto i = 0U; i < 8; ++i)
  { new (buffer + sizeof(Counter) * i) Counter {counter}; }
  REQUIRE(counter == 0);

  auto* ptr = reinterpret_cast<Counter*>(&buffer[0]);
  for (auto i = 0U; i < 8; ++i) { etl::destroy_at(ptr + i); }

  REQUIRE(counter == 8);
}

TEST_CASE("memory: destroy", "[memory]")
{
  struct Counter
  {
    int& value;
    Counter(int& v) : value(v) { }
    ~Counter() { value++; }
  };

  alignas(Counter) etl::byte buffer[sizeof(Counter) * 8];

  auto counter = 0;
  for (auto i = 0U; i < 8; ++i)
  { new (buffer + sizeof(Counter) * i) Counter {counter}; }
  REQUIRE(counter == 0);

  auto* ptr = reinterpret_cast<Counter*>(&buffer[0]);
  etl::destroy(ptr, ptr + 8);

  REQUIRE(counter == 8);
}

TEST_CASE("memory: destroy_n", "[memory]")
{
  struct Counter
  {
    int& value;
    Counter(int& v) : value(v) { }
    ~Counter() { value++; }
  };

  alignas(Counter) etl::byte buffer[sizeof(Counter) * 8];

  auto counter = 0;
  for (auto i = 0U; i < 8; ++i)
  { new (&buffer[0] + sizeof(Counter) * i) Counter {counter}; }
  REQUIRE(counter == 0);

  auto* ptr = reinterpret_cast<Counter*>(&buffer[0]);
  etl::destroy_n(ptr, 4);

  REQUIRE(counter == 4);
}
