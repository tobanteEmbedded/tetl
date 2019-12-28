/*
Copyright (c) 2019, Tobias Hienzsch
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
    REQUIRE(taetl::true_type::value == true);
}

TEST_CASE("type_traits: false_type", "[type_traits]")
{
    REQUIRE(taetl::false_type::value == false);
}

TEST_CASE("type_traits: is_same", "[type_traits]")
{
    REQUIRE(taetl::is_same<int, int>::value == true);
    REQUIRE(taetl::is_same<int, float>::value == false);

    REQUIRE(taetl::is_same_v<double, double> == true);
    REQUIRE(taetl::is_same_v<double, float> == false);
}

TEST_CASE("type_traits: is_void", "[type_traits]")
{
    REQUIRE(taetl::is_void<void>::value == true);
    REQUIRE(taetl::is_void<int>::value == false);

    REQUIRE(taetl::is_void_v<void> == true);
    REQUIRE(taetl::is_void_v<double> == false);
}

TEST_CASE("type_traits: is_integral", "[type_traits]")
{
    // true
    REQUIRE(taetl::is_integral_v<char> == true);
    REQUIRE(taetl::is_integral_v<unsigned char> == true);

    REQUIRE(taetl::is_integral_v<short> == true);
    REQUIRE(taetl::is_integral_v<unsigned short> == true);

    REQUIRE(taetl::is_integral_v<int> == true);
    REQUIRE(taetl::is_integral_v<unsigned int> == true);

    REQUIRE(taetl::is_integral_v<long> == true);
    REQUIRE(taetl::is_integral_v<unsigned long> == true);

    REQUIRE(taetl::is_integral_v<long long> == true);
    REQUIRE(taetl::is_integral_v<unsigned long long> == true);

    REQUIRE(taetl::is_integral_v<taetl::int8_t> == true);
    REQUIRE(taetl::is_integral_v<taetl::int16_t> == true);
    REQUIRE(taetl::is_integral_v<taetl::int32_t> == true);
    REQUIRE(taetl::is_integral_v<taetl::int64_t> == true);

    REQUIRE(taetl::is_integral_v<taetl::uint8_t> == true);
    REQUIRE(taetl::is_integral_v<taetl::uint16_t> == true);
    REQUIRE(taetl::is_integral_v<taetl::uint32_t> == true);
    REQUIRE(taetl::is_integral_v<taetl::uint64_t> == true);

    // false
    REQUIRE(taetl::is_integral_v<float> == false);
    REQUIRE(taetl::is_integral_v<double> == false);
    REQUIRE(taetl::is_integral_v<struct S> == false);
}

TEST_CASE("type_traits: is_floating_point", "[type_traits]")
{
    // true
    REQUIRE(taetl::is_floating_point_v<float> == true);
    REQUIRE(taetl::is_floating_point_v<double> == true);
    REQUIRE(taetl::is_floating_point_v<long double> == true);

    // false
    REQUIRE(taetl::is_floating_point_v<int> == false);
    REQUIRE(taetl::is_floating_point_v<taetl::int64_t> == false);
    REQUIRE(taetl::is_floating_point_v<struct S> == false);
}

TEST_CASE("type_traits: is_null_pointer", "[type_traits]")
{
    // true
    REQUIRE(taetl::is_null_pointer_v<decltype(nullptr)> == true);

    // false
    REQUIRE(taetl::is_null_pointer_v<int*> == false);
    REQUIRE(taetl::is_null_pointer_v<taetl::int64_t> == false);
    REQUIRE(taetl::is_null_pointer_v<double*> == false);
}

TEST_CASE("type_traits: is_array", "[type_traits]")
{
    // true
    REQUIRE(taetl::is_array_v<int[]> == true);
    REQUIRE(taetl::is_array_v<int[4]> == true);

    REQUIRE(taetl::is_array_v<double[]> == true);
    REQUIRE(taetl::is_array_v<double[4]> == true);

    // false
    REQUIRE(taetl::is_array_v<decltype(nullptr)> == false);
    REQUIRE(taetl::is_array_v<int*> == false);
    REQUIRE(taetl::is_array_v<taetl::int64_t> == false);
    REQUIRE(taetl::is_array_v<double*> == false);
}

TEST_CASE("type_traits: is_pointer", "[type_traits]")
{
    // true
    REQUIRE(taetl::is_pointer_v<int*> == true);
    REQUIRE(taetl::is_pointer_v<double*> == true);
    REQUIRE(taetl::is_pointer_v<struct S*> == true);

    // false
    REQUIRE(taetl::is_pointer_v<taetl::int64_t> == false);
    REQUIRE(taetl::is_pointer_v<double> == false);
    REQUIRE(taetl::is_pointer_v<struct T> == false);
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
    REQUIRE(taetl::is_class_v<S> == true);
    REQUIRE(taetl::is_class_v<C> == true);
    REQUIRE(taetl::is_class_v<struct X> == true);

    // false
    REQUIRE(taetl::is_class_v<taetl::int64_t> == false);
    REQUIRE(taetl::is_class_v<double> == false);
    REQUIRE(taetl::is_class_v<S*> == false);
    REQUIRE(taetl::is_class_v<C*> == false);
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
    REQUIRE(taetl::is_enum_v<E> == true);
    REQUIRE(taetl::is_enum_v<EC> == true);

    // false
    REQUIRE(taetl::is_enum_v<struct X> == false);
    REQUIRE(taetl::is_enum_v<taetl::int64_t> == false);
    REQUIRE(taetl::is_enum_v<double> == false);
    REQUIRE(taetl::is_enum_v<struct S*> == false);
    REQUIRE(taetl::is_enum_v<struct C*> == false);
}

TEST_CASE("type_traits: is_union", "[type_traits]")
{
    typedef union {
        int a;
        float b;
    } B;

    // true
    REQUIRE(taetl::is_union_v<B> == true);

    // false
    REQUIRE(taetl::is_union_v<struct X> == false);
    REQUIRE(taetl::is_union_v<taetl::int64_t> == false);
    REQUIRE(taetl::is_union_v<double> == false);
    REQUIRE(taetl::is_union_v<struct S*> == false);
    REQUIRE(taetl::is_union_v<struct C*> == false);
}
