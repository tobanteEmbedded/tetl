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

#include "etl/experimental/meta/meta.hpp"

#include "etl/cstdint.hpp"
#include "etl/type_traits.hpp"

#include "catch2/catch_template_test_macros.hpp"

namespace meta = etl::experimental::meta;

TEST_CASE("experimental/meta: int_c", "[experimental][meta]")
{
    using etl::integral_constant;
    using meta::int_c;
    using meta::type_c;

    STATIC_REQUIRE(int_c<0> + int_c<0> == int_c<0>);
    STATIC_REQUIRE(int_c<1> + int_c<1> == int_c<2>);
    STATIC_REQUIRE(int_c<1> + int_c<2> == int_c<3>);
    STATIC_REQUIRE(int_c<1> + int_c<3> == int_c<4>);

    // clang-format off
    STATIC_REQUIRE(type_c<decltype(int_c<1> + int_c<1>)> == type_c<integral_constant<int, 2>>);
    STATIC_REQUIRE(type_c<decltype(int_c<1> + int_c<2>)> == type_c<integral_constant<int, 3>>);
    STATIC_REQUIRE(type_c<decltype(int_c<1> + int_c<3>)> == type_c<integral_constant<int, 4>>);
    // clang-format on
}

TEST_CASE("experimental/meta: type_c", "[experimental][meta]")
{
    STATIC_REQUIRE(meta::type_c<int> == meta::type_c<int>);
    STATIC_REQUIRE(meta::type_c<int const> == meta::type_c<int const>);
    STATIC_REQUIRE(meta::type_c<int> != meta::type_c<int const>);

    // clang-format off
    STATIC_REQUIRE(etl::is_same_v<decltype(meta::type_c<int> == meta::type_c<int>), etl::bool_constant<true>>);
    STATIC_REQUIRE(etl::is_same_v<decltype(meta::type_c<int> != meta::type_c<int>), etl::bool_constant<false>>);

    STATIC_REQUIRE(decltype(meta::type_id(etl::declval<int const>())) {} == meta::type_c<int>);
    STATIC_REQUIRE(decltype(meta::type_id(etl::declval<int volatile>())) {} == meta::type_c<int>);
    STATIC_REQUIRE(decltype(meta::type_id(etl::declval<int const volatile>())) {} == meta::type_c<int>);
    // clang-format on
}

TEMPLATE_TEST_CASE("experimental/meta: make_type_tuple", "[experimental][meta]",
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;

    constexpr auto t = meta::make_type_tuple<int, T>();
    STATIC_REQUIRE(etl::get<0>(t) == meta::type_c<int>);
    STATIC_REQUIRE(etl::get<1>(t) == meta::type_c<T>);
}

TEMPLATE_TEST_CASE("experimental/meta: size_of", "[experimental][meta]",
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t)
{
    using T = TestType;
    using meta::size_c;
    using meta::size_of;
    using meta::type_c;

    REQUIRE(size_of(type_c<T>) == size_c<sizeof(T)>);
    REQUIRE(decltype(size_of(type_c<T>) == size_c<sizeof(T)>)::value);
}