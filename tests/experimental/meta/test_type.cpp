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
    STATIC_REQUIRE(meta::int_c<0> + meta::int_c<0> == meta::int_c<0>);
    STATIC_REQUIRE(meta::int_c<1> + meta::int_c<1> == meta::int_c<2>);
    STATIC_REQUIRE(meta::int_c<1> + meta::int_c<2> == meta::int_c<3>);
    STATIC_REQUIRE(meta::int_c<1> + meta::int_c<3> == meta::int_c<4>);
}

TEMPLATE_TEST_CASE("experimental/meta: is_pointer", "[experimental][meta]",
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;

    STATIC_REQUIRE(etl::is_same_v<typename meta::type<T>::name, T>);
    STATIC_REQUIRE(!meta::is_pointer(meta::type<T> {}));
    STATIC_REQUIRE(meta::is_pointer(meta::type<T*> {}));
    STATIC_REQUIRE(meta::is_pointer(meta::add_pointer(meta::type<T> {})));
}

TEMPLATE_TEST_CASE("experimental/meta: make_type_tuple", "[experimental][meta]",
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;
    using etl::get;
    using etl::is_same_v;

    auto t = meta::make_type_tuple<int, T>();
    STATIC_REQUIRE(
        is_same_v<typename etl::decay_t<decltype(get<0>(t))>::name, int>);
    STATIC_REQUIRE(
        is_same_v<typename etl::decay_t<decltype(get<1>(t))>::name, T>);
}

TEMPLATE_TEST_CASE("experimental/meta: for_each", "[experimental][meta]",
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    auto t       = meta::make_type_tuple<int, TestType, float, double>();
    auto counter = 0;
    meta::for_each(t, [&counter](auto const& x) {
        using etl::is_same_v;
        using T      = TestType;
        using type_t = typename etl::decay_t<decltype(x)>;
        if (counter == 0) { REQUIRE(is_same_v<typename type_t::name, int>); }
        if (counter == 1) { REQUIRE(is_same_v<typename type_t::name, T>); }
        if (counter == 2) { REQUIRE(is_same_v<typename type_t::name, float>); }
        if (counter == 3) { REQUIRE(is_same_v<typename type_t::name, double>); }
        counter++;
    });

    REQUIRE(counter == 4);
}

TEMPLATE_TEST_CASE("experimental/meta: all_of,any_of,none_of",
    "[experimental][meta]", etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double)
{
    auto const sizeGreater1 = [](auto t) {
        return etl::bool_constant<(sizeof(decltype(meta::type_id(t))) > 1)> {};
    };

    auto const sizeEqual16 = [](auto t) {
        constexpr auto is16bytes = sizeof(decltype(meta::type_id(t))) == 16;
        return etl::bool_constant<is16bytes> {};
    };

    auto l = meta::make_type_tuple<TestType, long, long long>();
    STATIC_REQUIRE(meta::all_of(l, sizeGreater1));
    STATIC_REQUIRE(meta::none_of(l, sizeEqual16));
    STATIC_REQUIRE(meta::any_of(l, sizeGreater1));
}