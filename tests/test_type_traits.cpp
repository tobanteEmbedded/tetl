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

#include "etl/map.hpp"
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

TEMPLATE_TEST_CASE("type_traits: is_same = false", "[type_traits]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double, struct CC,
                   class SS)
{
    REQUIRE(etl::is_same_v<struct S, TestType> == false);
    STATIC_REQUIRE(etl::is_same_v<struct S, TestType> == false);
}

TEMPLATE_TEST_CASE("type_traits: is_same = true", "[type_traits]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double, struct CC,
                   class SS)
{
    STATIC_REQUIRE(etl::is_same<TestType, TestType>::value == true);
}

TEMPLATE_TEST_CASE("type_traits: is_void = false", "[type_traits]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    STATIC_REQUIRE(etl::is_void<TestType>::value == false);
    STATIC_REQUIRE(etl::is_void_v<TestType> == false);
}

TEMPLATE_TEST_CASE("type_traits: is_void = true", "[type_traits]", void)
{
    STATIC_REQUIRE(etl::is_void<TestType>::value == true);
    STATIC_REQUIRE(etl::is_void_v<TestType> == true);
}

TEMPLATE_TEST_CASE("type_traits: is_integral = false", "[type_traits]", float, double,
                   long double, (struct S))
{
    STATIC_REQUIRE(etl::is_integral_v<TestType> == false);
}

TEMPLATE_TEST_CASE("type_traits: is_integral = true", "[type_traits]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t)
{
    STATIC_REQUIRE(etl::is_integral_v<TestType> == true);
}

TEMPLATE_TEST_CASE("type_traits: is_floating_point = true", "[type_traits]", float,
                   double, long double)
{
    STATIC_REQUIRE(etl::is_floating_point_v<TestType> == true);
}

TEMPLATE_TEST_CASE("type_traits: is_floating_point = false", "[type_traits]",
                   etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
                   etl::int32_t, etl::uint64_t, etl::int64_t, (struct S))
{
    STATIC_REQUIRE(etl::is_floating_point_v<TestType> == false);
}

TEMPLATE_TEST_CASE("type_traits: is_null_pointer = false", "[type_traits]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double, struct S)
{
    STATIC_REQUIRE(etl::is_null_pointer_v<TestType> == false);
}

TEST_CASE("type_traits: is_null_pointer = true", "[type_traits]")
{
    STATIC_REQUIRE(etl::is_null_pointer_v<decltype(nullptr)> == true);
}

TEMPLATE_TEST_CASE("type_traits: is_array = false", "[type_traits]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double, struct S)
{
    STATIC_REQUIRE(etl::is_array_v<TestType> == false);
}

TEMPLATE_TEST_CASE("type_traits: is_array = true", "[type_traits]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double, struct S)
{
    STATIC_REQUIRE(etl::is_array_v<TestType[]> == true);
    STATIC_REQUIRE(etl::is_array_v<TestType[4]> == true);
}

TEMPLATE_TEST_CASE("type_traits: is_pointer", "[type_traits]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double, struct S)
{
    STATIC_REQUIRE(etl::is_pointer_v<TestType*> == true);
    STATIC_REQUIRE(etl::is_pointer_v<TestType> == false);
}

TEMPLATE_TEST_CASE("type_traits: is_class = false", "[type_traits]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    STATIC_REQUIRE(etl::is_class_v<TestType> == false);
}

TEMPLATE_TEST_CASE("type_traits: is_class = true", "[type_traits]", struct S, struct CS)
{
    STATIC_REQUIRE(etl::is_class_v<TestType> == true);
    STATIC_REQUIRE(etl::is_class_v<struct X> == true);
}

TEMPLATE_TEST_CASE("type_traits: is_enum = false", "[type_traits]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    STATIC_REQUIRE(etl::is_enum_v<TestType> == false);
    STATIC_REQUIRE(etl::is_enum_v<TestType const> == false);
    STATIC_REQUIRE(etl::is_enum_v<TestType volatile> == false);
    STATIC_REQUIRE(etl::is_enum_v<TestType*> == false);
    STATIC_REQUIRE(etl::is_enum_v<TestType const*> == false);
    STATIC_REQUIRE(etl::is_enum_v<TestType const* const> == false);
    STATIC_REQUIRE(etl::is_enum_v<TestType&> == false);
    STATIC_REQUIRE(etl::is_enum_v<TestType const&> == false);
}

enum E
{
    one,
};

enum class EC
{
    nop,
};

TEMPLATE_TEST_CASE("type_traits: is_enum = true", "[type_traits]", E, EC)
{
    STATIC_REQUIRE(etl::is_enum_v<TestType> == true);
    STATIC_REQUIRE(etl::is_enum_v<TestType const> == true);
    STATIC_REQUIRE(etl::is_enum_v<TestType volatile> == true);
}

TEMPLATE_TEST_CASE("type_traits: is_union = false", "[type_traits]", etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double, E, EC)
{
    STATIC_REQUIRE(etl::is_union_v<TestType> == false);
    STATIC_REQUIRE(etl::is_union_v<TestType const> == false);
    STATIC_REQUIRE(etl::is_union_v<TestType volatile> == false);
    STATIC_REQUIRE(etl::is_union_v<TestType*> == false);
    STATIC_REQUIRE(etl::is_union_v<TestType const*> == false);
    STATIC_REQUIRE(etl::is_union_v<TestType const* const> == false);
    STATIC_REQUIRE(etl::is_union_v<TestType&> == false);
    STATIC_REQUIRE(etl::is_union_v<TestType const&> == false);
}

using UnionA = union
{
    double b;
    int a;
};

using UnionB = union
{
    int a;
    float b;
};

TEMPLATE_TEST_CASE("type_traits: is_union = true", "[type_traits]", UnionA, UnionB)
{
    STATIC_REQUIRE(etl::is_union_v<TestType> == true);
    STATIC_REQUIRE(etl::is_union_v<TestType const> == true);
    STATIC_REQUIRE(etl::is_union_v<TestType volatile> == true);
}

TEMPLATE_TEST_CASE("type_traits: is_arithmetic", "[type_traits]", bool, etl::uint8_t,
                   etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
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

class A
{
};
enum B : unsigned
{
};
enum class C : unsigned
{
};

TEMPLATE_TEST_CASE("type_traits: is_unsigned = false", "[type_traits]", etl::int8_t,
                   etl::int16_t, etl::int32_t, etl::int64_t, float, double, long double,
                   A, B, C)
{
    STATIC_REQUIRE_FALSE(etl::is_unsigned<TestType>::value);
    STATIC_REQUIRE_FALSE(etl::is_unsigned_v<TestType>);
}

TEMPLATE_TEST_CASE("type_traits: is_unsigned = true", "[type_traits]", etl::uint8_t,
                   etl::uint16_t, etl::uint32_t, etl::uint64_t)
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

TEMPLATE_TEST_CASE("type_traits: rank", "[type_traits]", bool, etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)

{
    STATIC_REQUIRE(etl::rank<TestType>::value == 0);
    STATIC_REQUIRE(etl::rank_v<TestType> == 0);

    STATIC_REQUIRE(etl::rank<TestType[5]>::value == 1);
    STATIC_REQUIRE(etl::rank<TestType[5][5]>::value == 2);
    STATIC_REQUIRE(etl::rank<TestType[][5][5]>::value == 3);
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

    STATIC_REQUIRE(etl::is_same_v<etl::make_unsigned_t<signed char>, unsigned char>);
    STATIC_REQUIRE(etl::is_same_v<etl::make_unsigned_t<signed short>, unsigned short>);
    STATIC_REQUIRE(etl::is_same_v<etl::make_unsigned_t<signed int>, unsigned int>);
    STATIC_REQUIRE(etl::is_same_v<etl::make_unsigned_t<signed long>, unsigned long>);
    STATIC_REQUIRE(
        etl::is_same_v<etl::make_unsigned_t<signed long long>, unsigned long long>);

    STATIC_REQUIRE(etl::is_same_v<etl::make_unsigned_t<unsigned char>, unsigned char>);
    STATIC_REQUIRE(etl::is_same_v<etl::make_unsigned_t<unsigned short>, unsigned short>);
    STATIC_REQUIRE(etl::is_same_v<etl::make_unsigned_t<unsigned int>, unsigned int>);
    STATIC_REQUIRE(etl::is_same_v<etl::make_unsigned_t<unsigned long>, unsigned long>);
    STATIC_REQUIRE(
        etl::is_same_v<etl::make_unsigned_t<unsigned long long>, unsigned long long>);
}

namespace
{
struct Ex1
{
    // member has a non-trivial default ctor
    etl::map<int, float, 4> str;
};

struct Ex2
{
    // trivial and non-throwing
    Ex2() = default;
    int n;
};

struct Ex3
{
    Ex3(int& _n) : n {_n} { }
    int& n;
};

}  // namespace

TEMPLATE_TEST_CASE("type_traits: is_default_constructible", "[type_traits]", int, float,
                   Ex1, Ex2)
{
    STATIC_REQUIRE(etl::is_default_constructible<TestType>::value);
    STATIC_REQUIRE(etl::is_default_constructible_v<TestType>);

    STATIC_REQUIRE_FALSE(etl::is_default_constructible_v<Ex3>);
}

TEMPLATE_TEST_CASE("type_traits: is_trivially_default_constructible", "[type_traits]",
                   int, float, Ex2)
{
    STATIC_REQUIRE(etl::is_trivially_default_constructible<TestType>::value);
    STATIC_REQUIRE(etl::is_trivially_default_constructible_v<TestType>);

    STATIC_REQUIRE_FALSE(etl::is_trivially_default_constructible_v<Ex1>);
    STATIC_REQUIRE_FALSE(etl::is_trivially_default_constructible_v<Ex3>);
}

TEMPLATE_TEST_CASE("type_traits: is_nothrow_default_constructible", "[type_traits]", int,
                   float, Ex2)
{
    STATIC_REQUIRE(etl::is_nothrow_default_constructible<TestType>::value);
    STATIC_REQUIRE(etl::is_nothrow_default_constructible_v<TestType>);
}