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

#include "etl/type_traits.hpp"

#include "catch2/catch.hpp"

TEST_CASE("type_traits: true_type", "[type_traits]")
{
    STATIC_REQUIRE(etl::true_type::value == true);
}

TEST_CASE("type_traits: false_type", "[type_traits]")
{
    STATIC_REQUIRE(etl::false_type::value == false);
}

TEMPLATE_TEST_CASE("type_traits: is_same = false", "[type_traits]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
    REQUIRE(etl::is_same_v<struct S, TestType> == false);
    STATIC_REQUIRE(etl::is_same_v<struct S, TestType> == false);
}

TEMPLATE_TEST_CASE("type_traits: is_same = true", "[type_traits]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double)
{
    STATIC_REQUIRE(etl::is_same<TestType, TestType>::value == true);
}

TEST_CASE("type_traits: is_void", "[type_traits]")
{
    STATIC_REQUIRE(etl::is_void<void>::value == true);
    STATIC_REQUIRE(etl::is_void<int>::value == false);

    STATIC_REQUIRE(etl::is_void_v<void> == true);
    STATIC_REQUIRE(etl::is_void_v<double> == false);
}

TEMPLATE_TEST_CASE("type_traits: is_integral = false", "[type_traits]", float,
                   double, long double, (struct S))
{
    STATIC_REQUIRE(etl::is_integral_v<TestType> == false);
}

TEMPLATE_TEST_CASE("type_traits: is_integral = true", "[type_traits]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t)
{
    STATIC_REQUIRE(etl::is_integral_v<TestType> == true);
}

TEMPLATE_TEST_CASE("type_traits: is_floating_point = true", "[type_traits]",
                   float, double, long double)
{
    STATIC_REQUIRE(etl::is_floating_point_v<TestType> == true);
}

TEMPLATE_TEST_CASE("type_traits: is_floating_point = false", "[type_traits]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   (struct S))
{
    STATIC_REQUIRE(etl::is_floating_point_v<TestType> == false);
}

TEMPLATE_TEST_CASE("type_traits: is_null_pointer = false", "[type_traits]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double, struct S)
{
    STATIC_REQUIRE(etl::is_null_pointer_v<TestType> == false);
}

TEST_CASE("type_traits: is_null_pointer = true", "[type_traits]")
{
    STATIC_REQUIRE(etl::is_null_pointer_v<decltype(nullptr)> == true);
}

TEMPLATE_TEST_CASE("type_traits: is_array = false", "[type_traits]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double, struct S)
{
    STATIC_REQUIRE(etl::is_array_v<TestType> == false);
}

TEMPLATE_TEST_CASE("type_traits: is_array = true", "[type_traits]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double, struct S)
{
    STATIC_REQUIRE(etl::is_array_v<TestType[]> == true);
    STATIC_REQUIRE(etl::is_array_v<TestType[4]> == true);
}

TEMPLATE_TEST_CASE("type_traits: is_pointer", "[type_traits]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, float, double,
                   long double, struct S)
{
    STATIC_REQUIRE(etl::is_pointer_v<TestType*> == true);
    STATIC_REQUIRE(etl::is_pointer_v<TestType> == false);
}

TEMPLATE_TEST_CASE("type_traits: is_class = false", "[type_traits]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
    STATIC_REQUIRE(etl::is_class_v<TestType> == false);
}

TEMPLATE_TEST_CASE("type_traits: is_class = true", "[type_traits]", struct S,
                   struct C)
{
    STATIC_REQUIRE(etl::is_class_v<TestType> == true);
    STATIC_REQUIRE(etl::is_class_v<struct X> == true);
}

TEST_CASE("type_traits: is_enum", "[type_traits]")
{
    enum E
    {
        one,
    };

    enum class EC
    {
        nop,
    };

    // true
    STATIC_REQUIRE(etl::is_enum_v<E> == true);
    STATIC_REQUIRE(etl::is_enum_v<EC> == true);

    // false
    STATIC_REQUIRE(etl::is_enum_v<struct X> == false);
    STATIC_REQUIRE(etl::is_enum_v<etl::int64_t> == false);
    STATIC_REQUIRE(etl::is_enum_v<double> == false);
    STATIC_REQUIRE(etl::is_enum_v<struct S*> == false);
    STATIC_REQUIRE(etl::is_enum_v<struct C*> == false);
}

TEST_CASE("type_traits: is_union", "[type_traits]")
{
    typedef union
    {
        int a;
        float b;
    } B;

    // true
    STATIC_REQUIRE(etl::is_union_v<B> == true);

    // false
    STATIC_REQUIRE(etl::is_union_v<struct X> == false);
    STATIC_REQUIRE(etl::is_union_v<etl::int64_t> == false);
    STATIC_REQUIRE(etl::is_union_v<double> == false);
    STATIC_REQUIRE(etl::is_union_v<struct S*> == false);
    STATIC_REQUIRE(etl::is_union_v<struct C*> == false);
}

TEMPLATE_TEST_CASE("type_traits: is_arithmetic", "[type_traits]", bool,
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t,
                   etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
                   float, double, long double)
{
    STATIC_REQUIRE(etl::is_arithmetic<TestType>::value);
    STATIC_REQUIRE(etl::is_arithmetic<TestType const>::value);
    STATIC_REQUIRE(etl::is_arithmetic<TestType volatile>::value);
    STATIC_REQUIRE_FALSE(etl::is_arithmetic<TestType&>::value);
    STATIC_REQUIRE_FALSE(etl::is_arithmetic<TestType const&>::value);
    STATIC_REQUIRE_FALSE(etl::is_arithmetic<TestType*>::value);
    STATIC_REQUIRE_FALSE(etl::is_arithmetic<TestType const*>::value);
    STATIC_REQUIRE_FALSE(etl::is_arithmetic<TestType const* const>::value);
}

TEMPLATE_TEST_CASE("type_traits: is_unsigned = false", "[type_traits]",
                   etl::int8_t, etl::int16_t, etl::int32_t, etl::int64_t, float,
                   double, long double)
{
    class A
    {
    };
    enum B : unsigned
    {
    };
    enum class C : unsigned
    {
    };

    STATIC_REQUIRE_FALSE(etl::is_unsigned<TestType>::value);
    STATIC_REQUIRE_FALSE(etl::is_unsigned_v<TestType>);
    STATIC_REQUIRE_FALSE(etl::is_unsigned<A>::value);
    STATIC_REQUIRE_FALSE(etl::is_unsigned<B>::value);
    STATIC_REQUIRE_FALSE(etl::is_unsigned<C>::value);
}

TEMPLATE_TEST_CASE("type_traits: is_unsigned = true", "[type_traits]",
                   etl::uint8_t, etl::uint16_t, etl::uint32_t, etl::uint64_t)
{
    STATIC_REQUIRE(etl::is_unsigned<TestType>::value);
}

TEST_CASE("type_traits: conditional", "[type_traits]")
{
    using etl::conditional;
    using etl::conditional_t;
    using Type1 = conditional<true, int, double>::type;
    using Type2 = conditional<false, int, double>::type;

    // true
    REQUIRE(typeid(Type1) == typeid(int));
    REQUIRE(typeid(Type2) == typeid(double));
    REQUIRE(typeid(conditional_t<false, int, double>) == typeid(double));

    // false
    REQUIRE_FALSE(typeid(Type1) == typeid(double));
    REQUIRE_FALSE(typeid(Type2) == typeid(int));
}

TEST_CASE("type_traits: rank", "[type_traits]")
{
    STATIC_REQUIRE(etl::rank<int>::value == 0);
    STATIC_REQUIRE(etl::rank_v<int> == 0);

    STATIC_REQUIRE(etl::rank<int[5]>::value == 1);
    STATIC_REQUIRE(etl::rank<int[5][5]>::value == 2);
    STATIC_REQUIRE(etl::rank<int[][5][5]>::value == 3);
}

TEST_CASE("type_traits: make_unsigned", "[type_traits]")
{
    STATIC_REQUIRE(etl::is_same_v<etl::make_unsigned_t<int8_t>, uint8_t>);
    STATIC_REQUIRE(etl::is_same_v<etl::make_unsigned_t<int16_t>, uint16_t>);
    STATIC_REQUIRE(etl::is_same_v<etl::make_unsigned_t<int32_t>, uint32_t>);
    STATIC_REQUIRE(etl::is_same_v<etl::make_unsigned_t<int64_t>, uint64_t>);

    STATIC_REQUIRE(etl::is_same_v<etl::make_unsigned_t<uint8_t>, uint8_t>);
    STATIC_REQUIRE(etl::is_same_v<etl::make_unsigned_t<uint16_t>, uint16_t>);
    STATIC_REQUIRE(etl::is_same_v<etl::make_unsigned_t<uint32_t>, uint32_t>);
    STATIC_REQUIRE(etl::is_same_v<etl::make_unsigned_t<uint64_t>, uint64_t>);

    STATIC_REQUIRE(
        etl::is_same_v<etl::make_unsigned_t<signed char>, unsigned char>);
    STATIC_REQUIRE(
        etl::is_same_v<etl::make_unsigned_t<signed short>, unsigned short>);
    STATIC_REQUIRE(
        etl::is_same_v<etl::make_unsigned_t<signed int>, unsigned int>);
    STATIC_REQUIRE(
        etl::is_same_v<etl::make_unsigned_t<signed long>, unsigned long>);
    STATIC_REQUIRE(etl::is_same_v<etl::make_unsigned_t<signed long long>,
                                  unsigned long long>);

    STATIC_REQUIRE(
        etl::is_same_v<etl::make_unsigned_t<unsigned char>, unsigned char>);
    STATIC_REQUIRE(
        etl::is_same_v<etl::make_unsigned_t<unsigned short>, unsigned short>);
    STATIC_REQUIRE(
        etl::is_same_v<etl::make_unsigned_t<unsigned int>, unsigned int>);
    STATIC_REQUIRE(
        etl::is_same_v<etl::make_unsigned_t<unsigned long>, unsigned long>);
    STATIC_REQUIRE(etl::is_same_v<etl::make_unsigned_t<unsigned long long>,
                                  unsigned long long>);
}