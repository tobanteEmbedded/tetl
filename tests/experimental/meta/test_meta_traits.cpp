/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/experimental/meta/meta.hpp"

#include "etl/cstdint.hpp"
#include "etl/type_traits.hpp"

#include "catch2/catch_template_test_macros.hpp"

namespace meta = etl::experimental::meta;

TEMPLATE_TEST_CASE("experimental/meta: is_same", "[experimental][meta]",
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;
    using meta::traits::add_pointer;
    using meta::traits::is_same;
    struct S {
    };

    STATIC_REQUIRE(is_same(meta::type_c<T>, meta::type_c<T>));
    STATIC_REQUIRE(is_same(meta::type_c<T const>, meta::type_c<T const>));
    STATIC_REQUIRE(is_same(meta::type_c<T volatile>, meta::type_c<T volatile>));

    STATIC_REQUIRE(!is_same(meta::type_c<T>, meta::type_c<S>));
    STATIC_REQUIRE(!is_same(meta::type_c<T const>, meta::type_c<S const>));
}

TEMPLATE_TEST_CASE("experimental/meta: is_pointer", "[experimental][meta]",
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;
    using meta::traits::add_pointer;
    using meta::traits::is_pointer;

    STATIC_REQUIRE(!is_pointer(meta::type<T> {}));
    STATIC_REQUIRE(is_pointer(meta::type<T*> {}));
    STATIC_REQUIRE(is_pointer(add_pointer(meta::type<T> {})));
}
