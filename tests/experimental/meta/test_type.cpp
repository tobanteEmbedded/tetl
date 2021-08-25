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
    using meta::traits::add_pointer;
    using meta::traits::is_pointer;

    STATIC_REQUIRE(etl::is_same_v<typename meta::type<T>::name, T>);
    STATIC_REQUIRE(!is_pointer(meta::type<T> {}));
    STATIC_REQUIRE(is_pointer(meta::type<T*> {}));
    STATIC_REQUIRE(is_pointer(add_pointer(meta::type<T> {})));
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

TEMPLATE_TEST_CASE("experimental/meta: for_each", "[experimental][meta]",
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    auto t       = meta::make_type_tuple<int, TestType, float, double>();
    auto counter = 0;
    meta::for_each(t, [&counter](auto x) {
        if (counter == 0) { REQUIRE(x == meta::type_c<int>); }
        if (counter == 1) { REQUIRE(x == meta::type_c<TestType>); }
        if (counter == 2) { REQUIRE(x == meta::type_c<float>); }
        if (counter == 3) { REQUIRE(x == meta::type_c<double>); }
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

TEMPLATE_TEST_CASE("experimental/meta: transform", "[experimental][meta]",
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t, float, double)
{
    using T = TestType;
    using etl::tuple_element_t;
    using meta::type_c;

    auto old    = etl::tuple<T, long, int>();
    using old_t = decltype(old);
    STATIC_REQUIRE(type_c<tuple_element_t<0, old_t>> == type_c<T>);
    STATIC_REQUIRE(type_c<tuple_element_t<1, old_t>> == type_c<long>);
    STATIC_REQUIRE(type_c<tuple_element_t<2, old_t>> == type_c<int>);

    auto transformed = meta::transform(old, [](auto /*t*/) { return 0; });
    using new_t      = decltype(transformed);
    STATIC_REQUIRE(type_c<tuple_element_t<0, new_t>> == type_c<int>);
    STATIC_REQUIRE(type_c<tuple_element_t<1, new_t>> == type_c<int>);
    STATIC_REQUIRE(type_c<tuple_element_t<2, new_t>> == type_c<int>);
}