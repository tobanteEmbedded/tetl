/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/exception.hpp"
#include "etl/stdexcept.hpp"

#include "etl/type_traits.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEST_CASE("exception: excption", "[exception]")
{
    STATIC_REQUIRE(etl::is_default_constructible_v<etl::exception>);
    STATIC_REQUIRE(etl::is_constructible_v<etl::exception, char const*>);
}