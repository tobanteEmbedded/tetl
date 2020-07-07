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

#include "taetl/type_traits.hpp"

#include "catch2/catch.hpp"

TEST_CASE("type_traits: true_type", "[type_traits]")
{
    STATIC_REQUIRE(taetl::true_type::value == true);
}

TEST_CASE("type_traits: false_type", "[type_traits]")
{
    STATIC_REQUIRE(taetl::false_type::value == false);
}

TEST_CASE("type_traits: is_same", "[type_traits]")
{
    STATIC_REQUIRE(taetl::is_same<int, int>::value == true);
    STATIC_REQUIRE(taetl::is_same<int, float>::value == false);

    STATIC_REQUIRE(taetl::is_same_v<double, double> == true);
    STATIC_REQUIRE(taetl::is_same_v<double, float> == false);
}

TEST_CASE("type_traits: is_void", "[type_traits]")
{
    STATIC_REQUIRE(taetl::is_void<void>::value == true);
    STATIC_REQUIRE(taetl::is_void<int>::value == false);

    STATIC_REQUIRE(taetl::is_void_v<void> == true);
    STATIC_REQUIRE(taetl::is_void_v<double> == false);
}

TEST_CASE("type_traits: is_integral", "[type_traits]")
{
    // true
    STATIC_REQUIRE(taetl::is_integral_v<char> == true);
    STATIC_REQUIRE(taetl::is_integral_v<unsigned char> == true);

    STATIC_REQUIRE(taetl::is_integral_v<short> == true);
    STATIC_REQUIRE(taetl::is_integral_v<unsigned short> == true);

    STATIC_REQUIRE(taetl::is_integral_v<int> == true);
    STATIC_REQUIRE(taetl::is_integral_v<unsigned int> == true);

    STATIC_REQUIRE(taetl::is_integral_v<long> == true);
    STATIC_REQUIRE(taetl::is_integral_v<unsigned long> == true);

    STATIC_REQUIRE(taetl::is_integral_v<long long> == true);
    STATIC_REQUIRE(taetl::is_integral_v<unsigned long long> == true);

    STATIC_REQUIRE(taetl::is_integral_v<taetl::int8_t> == true);
    STATIC_REQUIRE(taetl::is_integral_v<taetl::int16_t> == true);
    STATIC_REQUIRE(taetl::is_integral_v<taetl::int32_t> == true);
    STATIC_REQUIRE(taetl::is_integral_v<taetl::int64_t> == true);

    STATIC_REQUIRE(taetl::is_integral_v<taetl::uint8_t> == true);
    STATIC_REQUIRE(taetl::is_integral_v<taetl::uint16_t> == true);
    STATIC_REQUIRE(taetl::is_integral_v<taetl::uint32_t> == true);
    STATIC_REQUIRE(taetl::is_integral_v<taetl::uint64_t> == true);

    // false
    STATIC_REQUIRE(taetl::is_integral_v<float> == false);
    STATIC_REQUIRE(taetl::is_integral_v<double> == false);
    STATIC_REQUIRE(taetl::is_integral_v<struct S> == false);
}

TEST_CASE("type_traits: is_floating_point", "[type_traits]")
{
    // true
    STATIC_REQUIRE(taetl::is_floating_point_v<float> == true);
    STATIC_REQUIRE(taetl::is_floating_point_v<double> == true);
    STATIC_REQUIRE(taetl::is_floating_point_v<long double> == true);

    // false
    STATIC_REQUIRE(taetl::is_floating_point_v<int> == false);
    STATIC_REQUIRE(taetl::is_floating_point_v<taetl::int64_t> == false);
    STATIC_REQUIRE(taetl::is_floating_point_v<struct S> == false);
}

TEST_CASE("type_traits: is_null_pointer", "[type_traits]")
{
    // true
    STATIC_REQUIRE(taetl::is_null_pointer_v<decltype(nullptr)> == true);

    // false
    STATIC_REQUIRE(taetl::is_null_pointer_v<int*> == false);
    STATIC_REQUIRE(taetl::is_null_pointer_v<taetl::int64_t> == false);
    STATIC_REQUIRE(taetl::is_null_pointer_v<double*> == false);
}

TEST_CASE("type_traits: is_array", "[type_traits]")
{
    // true
    STATIC_REQUIRE(taetl::is_array_v<int[]> == true);
    STATIC_REQUIRE(taetl::is_array_v<int[4]> == true);

    STATIC_REQUIRE(taetl::is_array_v<double[]> == true);
    STATIC_REQUIRE(taetl::is_array_v<double[4]> == true);

    // false
    STATIC_REQUIRE(taetl::is_array_v<decltype(nullptr)> == false);
    STATIC_REQUIRE(taetl::is_array_v<int*> == false);
    STATIC_REQUIRE(taetl::is_array_v<taetl::int64_t> == false);
    STATIC_REQUIRE(taetl::is_array_v<double*> == false);
}

TEST_CASE("type_traits: is_pointer", "[type_traits]")
{
    // true
    STATIC_REQUIRE(taetl::is_pointer_v<int*> == true);
    STATIC_REQUIRE(taetl::is_pointer_v<double*> == true);
    STATIC_REQUIRE(taetl::is_pointer_v<struct S*> == true);

    // false
    STATIC_REQUIRE(taetl::is_pointer_v<taetl::int64_t> == false);
    STATIC_REQUIRE(taetl::is_pointer_v<double> == false);
    STATIC_REQUIRE(taetl::is_pointer_v<struct T> == false);
}

TEST_CASE("type_traits: is_class", "[type_traits]")
{
    struct S
    {
    };

    class C
    {
    };

    // true
    STATIC_REQUIRE(taetl::is_class_v<S> == true);
    STATIC_REQUIRE(taetl::is_class_v<C> == true);
    STATIC_REQUIRE(taetl::is_class_v<struct X> == true);

    // false
    STATIC_REQUIRE(taetl::is_class_v<taetl::int64_t> == false);
    STATIC_REQUIRE(taetl::is_class_v<double> == false);
    STATIC_REQUIRE(taetl::is_class_v<S*> == false);
    STATIC_REQUIRE(taetl::is_class_v<C*> == false);
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
    STATIC_REQUIRE(taetl::is_enum_v<E> == true);
    STATIC_REQUIRE(taetl::is_enum_v<EC> == true);

    // false
    STATIC_REQUIRE(taetl::is_enum_v<struct X> == false);
    STATIC_REQUIRE(taetl::is_enum_v<taetl::int64_t> == false);
    STATIC_REQUIRE(taetl::is_enum_v<double> == false);
    STATIC_REQUIRE(taetl::is_enum_v<struct S*> == false);
    STATIC_REQUIRE(taetl::is_enum_v<struct C*> == false);
}

TEST_CASE("type_traits: is_union", "[type_traits]")
{
    typedef union
    {
        int a;
        float b;
    } B;

    // true
    STATIC_REQUIRE(taetl::is_union_v<B> == true);

    // false
    STATIC_REQUIRE(taetl::is_union_v<struct X> == false);
    STATIC_REQUIRE(taetl::is_union_v<taetl::int64_t> == false);
    STATIC_REQUIRE(taetl::is_union_v<double> == false);
    STATIC_REQUIRE(taetl::is_union_v<struct S*> == false);
    STATIC_REQUIRE(taetl::is_union_v<struct C*> == false);
}

TEST_CASE("type_traits: is_arithmetic", "[type_traits]")
{
    STATIC_REQUIRE(taetl::is_arithmetic<bool>::value);
    STATIC_REQUIRE(taetl::is_arithmetic<int>::value);
    STATIC_REQUIRE(taetl::is_arithmetic<int const>::value);
    STATIC_REQUIRE(taetl::is_arithmetic_v<float>);
    STATIC_REQUIRE(taetl::is_arithmetic_v<float const>);
    STATIC_REQUIRE(taetl::is_arithmetic_v<char>);
    STATIC_REQUIRE(taetl::is_arithmetic_v<char const>);

    STATIC_REQUIRE_FALSE(taetl::is_arithmetic<int&>::value);
    STATIC_REQUIRE_FALSE(taetl::is_arithmetic<int*>::value);
    STATIC_REQUIRE_FALSE(taetl::is_arithmetic<float&>::value);
    STATIC_REQUIRE_FALSE(taetl::is_arithmetic<float*>::value);
    STATIC_REQUIRE_FALSE(taetl::is_arithmetic<char&>::value);
    STATIC_REQUIRE_FALSE(taetl::is_arithmetic<char*>::value);
}

TEST_CASE("type_traits: is_unsigned", "[type_traits]")
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

    STATIC_REQUIRE(taetl::is_unsigned<unsigned int>::value);

    STATIC_REQUIRE_FALSE(taetl::is_unsigned<A>::value);
    STATIC_REQUIRE_FALSE(taetl::is_unsigned<float>::value);
    STATIC_REQUIRE_FALSE(taetl::is_unsigned<signed int>::value);
    STATIC_REQUIRE_FALSE(taetl::is_unsigned<B>::value);
    STATIC_REQUIRE_FALSE(taetl::is_unsigned<C>::value);
}

TEST_CASE("type_traits: conditional", "[type_traits]")
{
    using taetl::conditional;
    using taetl::conditional_t;
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
