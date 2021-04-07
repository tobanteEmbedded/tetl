/*
Copyright (c) Tobias Hienzsch. All rights reserved.

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

#include "etl/experimental/dsp/dsp.hpp"

TEMPLATE_TEST_CASE("experimental/dsp: identity", "[dsp][experimental]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
  auto id = etl::dsp::identity {};
  REQUIRE(id(TestType {0}) == TestType {0});
}

TEMPLATE_TEST_CASE("experimental/dsp: constant", "[dsp][experimental]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
  REQUIRE(etl::dsp::constant {TestType {0}}() == TestType {0});
  REQUIRE(etl::dsp::constant {TestType {42}}() == TestType {42});
}

TEST_CASE("experimental/dsp: constant literal", "[dsp][experimental]")
{
  using namespace etl::dsp::literals;
  REQUIRE(0.0_K() == 0.0L);
  REQUIRE(42_K() == 42);
}

TEMPLATE_TEST_CASE("experimental/dsp: pipe", "[dsp][experimental]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
  using T  = TestType;
  auto in  = etl::dsp::identity {};
  auto foo = [](T v) -> T { return static_cast<T>(v * 3); };
  auto bar = [](T v) -> T { return static_cast<T>(v * 2); };
  auto f   = in | foo | bar;

  REQUIRE(f(T(0)) == T(0));
  REQUIRE(f(T(2)) == T(12));
  REQUIRE(f(T(3)) == T(18));
}

TEMPLATE_TEST_CASE("experimental/dsp: delay", "[dsp][experimental]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
  WHEN("by zero (no delay)")
  {
    auto in = etl::dsp::identity {};
    auto f  = in | etl::dsp::Z<0, TestType>();
    REQUIRE(f(TestType {0}) == TestType {0});
    REQUIRE(f(TestType {2}) == TestType {2});
    REQUIRE(f(TestType {3}) == TestType {3});
  }

  WHEN("by one")
  {
    auto in = etl::dsp::identity {};
    auto f  = in | etl::dsp::Z<-1, TestType>();
    REQUIRE(f(TestType {0}) == TestType {0});
    REQUIRE(f(TestType {2}) == TestType {0});
    REQUIRE(f(TestType {3}) == TestType {2});
    REQUIRE(f(TestType {4}) == TestType {3});
  }

  WHEN("by two")
  {
    auto in = etl::dsp::identity {};
    auto f  = in | etl::dsp::Z<-2, TestType>();
    REQUIRE(f(TestType {0}) == TestType {0});
    REQUIRE(f(TestType {2}) == TestType {0});
    REQUIRE(f(TestType {3}) == TestType {0});
    REQUIRE(f(TestType {4}) == TestType {2});
  }
}

TEMPLATE_TEST_CASE("experimental/dsp: feedback_drain", "[dsp][experimental]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
  WHEN("No feedback is applied")
  {
    auto drain = etl::dsp::feedback_drain<TestType> {};
    REQUIRE(drain(TestType {0}) == TestType {0});
    REQUIRE(drain(TestType {1}) == TestType {1});
    REQUIRE(drain(TestType {2}) == TestType {2});
    REQUIRE(drain(TestType {3}) == TestType {3});
  }

  WHEN("Feedback is applied")
  {
    auto drain = etl::dsp::feedback_drain<TestType> {};
    drain.push(TestType {1});
    REQUIRE(drain(TestType {0}) == TestType {1});
  }
}

TEMPLATE_TEST_CASE("experimental/dsp: feedback_tap", "[dsp][experimental]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
  WHEN("Pass Through")
  {
    auto drain = etl::dsp::feedback_drain<TestType> {};
    auto tap   = etl::dsp::feedback_tap<TestType> {drain};
    REQUIRE(tap(TestType {0}) == TestType {0});
    REQUIRE(tap(TestType {1}) == TestType {1});
  }

  WHEN("Pass to drain")
  {
    auto drain = etl::dsp::feedback_drain<TestType> {};
    auto tap   = etl::dsp::feedback_tap<TestType> {drain};

    REQUIRE(tap(TestType {1}) == TestType {1});
    REQUIRE(drain(TestType {0}) == TestType {1});

    REQUIRE(tap(TestType {0}) == TestType {0});
    REQUIRE(drain(TestType {0}) == TestType {0});

    REQUIRE(tap(TestType {2}) == TestType {2});
    REQUIRE(drain(TestType {0}) == TestType {2});
  }
}

// TODO
// TEST_CASE("experimental/dsp: feedback chain", "[dsp][experimental]")
// {
//     auto in    = etl::dsp::identity {};
//     auto drain = etl::dsp::feedback_drain {};
//     // auto tap   = etl::dsp::feedback_tap {drain};
//     auto chain = in | drain;  // | tap;
//     REQUIRE(chain(1.0f) == 1.0f);
//     REQUIRE(chain(0.0f) == 0.0f);

//     drain.push(0.5f);
//     REQUIRE(chain(0.0f) == 0.5f);
// }
