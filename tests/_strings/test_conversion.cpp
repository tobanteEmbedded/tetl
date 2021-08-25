/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/version.hpp"

#include "etl/cstdint.hpp"
#include "etl/iterator.hpp"
#include "etl/system_error.hpp"
#include "etl/type_traits.hpp"

#include "etl/_strings/conversion.hpp"

#include "etl/string_view.hpp"

#include "catch2/catch_approx.hpp"
#include "catch2/catch_template_test_macros.hpp"
#include "catch2/generators/catch_generators.hpp"

using namespace etl::string_view_literals;
using namespace Catch::Generators;
using namespace etl::detail;

TEST_CASE("detail/string_conversion: int_to_ascii<int>",
    "[detail][string_conversion]")
{
    auto [input, expected] = GENERATE(table<int, etl::string_view>({
        { 0, "0"_sv },
        { 10, "10"_sv },
        { -10, "-10"_sv },
        { 99, "99"_sv },
        { -99, "-99"_sv },
        { 143, "143"_sv },
        { 999, "999"_sv },
        { -999, "-999"_sv },
        { 1111, "1111"_sv },
        { 123456789, "123456789"_sv },
        { -123456789, "-123456789"_sv },
    }));

    char buf[12] = {};
    auto res     = int_to_ascii(input, etl::begin(buf), 10, sizeof(buf));
    REQUIRE(res.error == int_to_ascii_error::none);
    REQUIRE(etl::string_view { buf } == expected);
    // REQUIRE(result == etl::begin(buf));
}

TEMPLATE_TEST_CASE("detail/string_conversion: ascii_to_floating_point",
    "[detail][string_conversion]", float, double, long double)
{
    using T = TestType;

    REQUIRE(ascii_to_floating_point<T>("0") == Catch::Approx(0.0F));
    REQUIRE(ascii_to_floating_point<T>("10") == Catch::Approx(10.0F));
    REQUIRE(ascii_to_floating_point<T>("100.0") == Catch::Approx(100.0F));
    REQUIRE(ascii_to_floating_point<T>("1000.000") == Catch::Approx(1000.0F));
    REQUIRE(ascii_to_floating_point<T>("10000") == Catch::Approx(10000.0F));
    REQUIRE(ascii_to_floating_point<T>("999999.0") == Catch::Approx(999999.0F));
    REQUIRE(ascii_to_floating_point<T>("9999999") == Catch::Approx(9999999.0F));
}