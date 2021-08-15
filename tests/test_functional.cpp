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
#include "etl/functional.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEMPLATE_TEST_CASE("functional: plus", "[functional]", int, float, double)
{
    STATIC_REQUIRE(etl::detail::is_transparent<etl::plus<>, TestType>::value);
    CHECK(etl::plus<TestType> {}(TestType { 2 }, TestType { 1 })
          == TestType { 3 });
    CHECK(etl::plus<TestType> {}(TestType { 1 }, TestType { 1 })
          == TestType { 2 });
    CHECK(etl::plus<TestType> {}(TestType { 100 }, TestType { 100 })
          == TestType { 200 });

    CHECK(etl::plus<> {}(TestType { 2 }, TestType { 1 }) == TestType { 3 });
    CHECK(etl::plus<> {}(TestType { 1 }, TestType { 1 }) == TestType { 2 });
    CHECK(
        etl::plus<> {}(TestType { 100 }, TestType { 100 }) == TestType { 200 });
}

TEMPLATE_TEST_CASE("functional: minus", "[functional]", int, float, double)
{
    STATIC_REQUIRE(etl::detail::is_transparent<etl::minus<>, TestType>::value);
    CHECK(etl::minus<TestType> {}(TestType { 99 }, 98) == TestType { 1 });
    CHECK(etl::minus<> {}(TestType { 2 }, TestType { 1 }) == TestType { 1 });
    CHECK(etl::minus<> {}(TestType { 1 }, TestType { 1 }) == TestType { 0 });
    CHECK(
        etl::minus<> {}(TestType { 99 }, TestType { 100 }) == TestType { -1 });

    CHECK(etl::minus<TestType> {}(TestType { 99 }, TestType { 98 })
          == TestType { 1 });
}

TEMPLATE_TEST_CASE("functional: multiplies", "[functional]", int, float, double)
{
    STATIC_REQUIRE(
        etl::detail::is_transparent<etl::multiplies<>, TestType>::value);

    CHECK(etl::multiplies<TestType> {}(TestType { 99 }, 2) == TestType { 198 });
    CHECK(
        etl::multiplies<> {}(TestType { 2 }, TestType { 1 }) == TestType { 2 });
    CHECK(
        etl::multiplies<> {}(TestType { 1 }, TestType { 1 }) == TestType { 1 });
    CHECK(etl::multiplies<> {}(TestType { 99 }, TestType { 100 })
          == TestType { 9900 });

    CHECK(etl::multiplies<TestType> {}(TestType { 99 }, TestType { 1 })
          == TestType { 99 });
}

TEMPLATE_TEST_CASE("functional: divides", "[functional]", int, float, double)
{
    STATIC_REQUIRE(
        etl::detail::is_transparent<etl::divides<>, TestType>::value);

    CHECK(etl::divides<TestType> {}(TestType { 100 }, 2) == TestType { 50 });
    CHECK(etl::divides<> {}(TestType { 2 }, TestType { 1 }) == TestType { 2 });
    CHECK(etl::divides<> {}(TestType { 1 }, TestType { 1 }) == TestType { 1 });
    CHECK(etl::divides<> {}(TestType { 100 }, TestType { 100 })
          == TestType { 1 });

    CHECK(etl::divides<TestType> {}(TestType { 99 }, TestType { 1 })
          == TestType { 99 });
}

TEMPLATE_TEST_CASE("functional: modulus", "[functional]", int, unsigned)
{
    STATIC_REQUIRE(
        etl::detail::is_transparent<etl::modulus<>, TestType>::value);

    CHECK(etl::modulus<TestType> {}(TestType { 100 }, 2) == TestType { 0 });
    CHECK(etl::modulus<> {}(TestType { 2 }, TestType { 1 }) == TestType { 0 });
    CHECK(etl::modulus<> {}(TestType { 5 }, TestType { 3 }) == TestType { 2 });
    CHECK(
        etl::modulus<> {}(TestType { 100 }, TestType { 99 }) == TestType { 1 });

    CHECK(etl::modulus<TestType> {}(TestType { 99 }, TestType { 90 })
          == TestType { 9 });
}

TEMPLATE_TEST_CASE("functional: negate", "[functional]", int, float, double)
{
    STATIC_REQUIRE(etl::detail::is_transparent<etl::negate<>, TestType>::value);

    CHECK(etl::negate<TestType> {}(TestType { 50 }) == TestType { -50 });
    CHECK(etl::negate<> {}(TestType { 2 }) == TestType { -2 });
    CHECK(etl::negate<> {}(TestType { -1 }) == TestType { 1 });
    CHECK(etl::negate<> {}(TestType { 100 }) == TestType { -100 });

    CHECK(etl::negate<TestType> {}(TestType { 99 }) == TestType { -99 });
}

TEMPLATE_TEST_CASE("functional: equal_to", "[functional]", int, float, double)
{
    REQUIRE(etl::equal_to<TestType> {}(TestType { 99 }, 99));
    REQUIRE(etl::equal_to<> {}(TestType { 1 }, TestType { 1 }));

    REQUIRE_FALSE(etl::equal_to<> {}(TestType { 2 }, TestType { 1 }));
    REQUIRE_FALSE(etl::equal_to<> {}(TestType { 99 }, TestType { 100 }));
    REQUIRE_FALSE(etl::equal_to<TestType> {}(TestType { 99 }, TestType { 98 }));
}

TEMPLATE_TEST_CASE(
    "functional: not_equal_to", "[functional]", int, float, double)
{
    REQUIRE_FALSE(etl::not_equal_to<TestType> {}(TestType { 99 }, 99));
    REQUIRE_FALSE(etl::not_equal_to<> {}(TestType { 1 }, TestType { 1 }));

    REQUIRE(etl::not_equal_to<> {}(TestType { 2 }, TestType { 1 }));
    REQUIRE(etl::not_equal_to<> {}(TestType { 99 }, TestType { 100 }));
    REQUIRE(etl::not_equal_to<TestType> {}(TestType { 99 }, TestType { 98 }));
}

TEMPLATE_TEST_CASE("functional: greater", "[functional]", int, float, double)
{
    REQUIRE_FALSE(etl::greater<TestType> {}(TestType { 99 }, 99));
    REQUIRE_FALSE(etl::greater<> {}(TestType { 1 }, TestType { 1 }));

    REQUIRE(etl::greater<> {}(TestType { 2 }, TestType { 1 }));
    REQUIRE(etl::greater<> {}(TestType { 101 }, TestType { 100 }));
    REQUIRE(etl::greater<TestType> {}(TestType { 99 }, TestType { 98 }));
}

TEMPLATE_TEST_CASE(
    "functional: greater_equal", "[functional]", int, float, double)
{
    REQUIRE_FALSE(etl::greater_equal<TestType> {}(TestType { 99 }, 100));
    REQUIRE_FALSE(etl::greater_equal<> {}(TestType { 1 }, TestType { 2 }));

    REQUIRE(etl::greater_equal<> {}(TestType { 2 }, TestType { 1 }));
    REQUIRE(etl::greater_equal<> {}(TestType { 100 }, TestType { 100 }));
    REQUIRE(etl::greater_equal<TestType> {}(TestType { 99 }, TestType { 98 }));
}

TEMPLATE_TEST_CASE("functional: less", "[functional]", int, float, double)
{
    REQUIRE(etl::less<TestType> {}(TestType { 99 }, 100));
    REQUIRE(etl::less<> {}(TestType { 1 }, TestType { 2 }));

    REQUIRE_FALSE(etl::less<> {}(TestType { 2 }, TestType { 1 }));
    REQUIRE_FALSE(etl::less<> {}(TestType { 101 }, TestType { 100 }));
    REQUIRE_FALSE(etl::less<TestType> {}(TestType { 99 }, TestType { 98 }));
}

TEMPLATE_TEST_CASE("functional: less_equal", "[functional]", int, float, double)
{
    REQUIRE(etl::less_equal<TestType> {}(TestType { 100 }, 100));
    REQUIRE(etl::less_equal<> {}(TestType { 1 }, TestType { 2 }));

    REQUIRE_FALSE(etl::less_equal<> {}(TestType { 2 }, TestType { 1 }));
    REQUIRE_FALSE(etl::less_equal<> {}(TestType { 1024 }, TestType { 100 }));
    REQUIRE_FALSE(
        etl::less_equal<TestType> {}(TestType { 99 }, TestType { 98 }));
}

TEST_CASE("functional: logical_and", "[functional]")
{
    REQUIRE_FALSE(etl::logical_and<bool> {}(true, false));
    REQUIRE(etl::logical_and<bool> {}(true, true));
    REQUIRE(etl::logical_and<> {}(true, true));
}

TEST_CASE("functional: logical_or", "[functional]")
{
    REQUIRE_FALSE(etl::logical_or<bool> {}(false, false));
    REQUIRE(etl::logical_or<bool> {}(false, true));
    REQUIRE(etl::logical_or<> {}(true, false));
}

TEST_CASE("functional: logical_not", "[functional]")
{
    REQUIRE_FALSE(etl::logical_not<bool> {}(true));
    REQUIRE(etl::logical_not<bool> {}(false));
    REQUIRE(etl::logical_not<> {}(false));
}

TEST_CASE("functional: bit_and", "[functional]")
{
    REQUIRE(etl::bit_and<etl::uint8_t> {}(0b0000'0101, 0b0000'1001) == 1);
    REQUIRE(etl::bit_and<etl::uint8_t> {}(1, 0) == 0);
    REQUIRE(etl::bit_and<> {}(1, 1) == 1);
}

TEST_CASE("functional: bit_or", "[functional]")
{
    REQUIRE(
        etl::bit_or<etl::uint8_t> {}(0b0000'0101, 0b0000'1001) == 0b0000'1101);
    REQUIRE(etl::bit_or<etl::uint8_t> {}(1, 0) == 1);
    REQUIRE(etl::bit_or<> {}(1, 1) == 1);
}

TEST_CASE("functional: bit_xor", "[functional]")
{
    REQUIRE(
        etl::bit_xor<etl::uint8_t> {}(0b0000'0101, 0b0000'1001) == 0b0000'1100);
    REQUIRE(etl::bit_xor<etl::uint8_t> {}(1, 0) == 1);
    REQUIRE(etl::bit_xor<> {}(1, 1) == 0);
}

TEST_CASE("functional: bit_not", "[functional]")
{
    REQUIRE(etl::bit_not<etl::uint8_t> {}(0b0000'0101) == 0b1111'1010);
}

TEST_CASE("functional: hash", "[functional]")
{
    CHECK(etl::hash<bool> {}(true) != 0);

    CHECK(etl::hash<char16_t> {}('a') != 0);
    CHECK(etl::hash<char32_t> {}('a') != 0);
    CHECK(etl::hash<wchar_t> {}('a') != 0);

    CHECK(etl::hash<signed char> {}(42) != 0);
    CHECK(etl::hash<unsigned char> {}(143) != 0);
    CHECK(etl::hash<short> {}(143) != 0);
    CHECK(etl::hash<unsigned short> {}(143) != 0);
    CHECK(etl::hash<int> {}(143) != 0);
    CHECK(etl::hash<unsigned int> {}(143) != 0);
    CHECK(etl::hash<long> {}(143) != 0);
    CHECK(etl::hash<unsigned long> {}(143) != 0);
    CHECK(etl::hash<long long> {}(143) != 0);
    CHECK(etl::hash<unsigned long long> {}(143) != 0);

    CHECK(etl::hash<float> {}(143) != 0);
    CHECK(etl::hash<double> {}(143) != 0);
    CHECK(etl::hash<long double> {}(143) != 0);

    etl::array<float, 4> data {};
    CHECK(etl::hash<decltype(data)*> {}(&data) != 0);

    CHECK(etl::hash<etl::nullptr_t> {}(nullptr) == 0);
}

TEST_CASE("functional: invoke", "[functional]")
{
    auto lambda = [](int x) -> int { return x; };
    REQUIRE(etl::invoke(lambda, 1) == 1);
    REQUIRE(etl::invoke([]() { return 42; }) == 42);
}

TEMPLATE_TEST_CASE(
    "functional: inplace_function", "[functional]", int, float, double)
{
    auto func = etl::inplace_function<TestType(TestType)> {
        [](TestType x) { return x + TestType(1); },
    };

    REQUIRE(func(TestType { 41 }) == TestType { 42 });
    REQUIRE(etl::invoke(func, TestType { 41 }) == TestType { 42 });
}