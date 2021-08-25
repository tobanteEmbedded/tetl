/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/version.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEST_CASE("version: language_standard", "[vector]")
{
    using etl::language_standard;

    REQUIRE(language_standard::cpp_17 == language_standard::cpp_17);
    REQUIRE(language_standard::cpp_20 == language_standard::cpp_20);
    REQUIRE(language_standard::cpp_23 == language_standard::cpp_23);

    REQUIRE(language_standard::cpp_17 < language_standard::cpp_20);
    REQUIRE(language_standard::cpp_17 < language_standard::cpp_23);

    REQUIRE(language_standard::cpp_20 > language_standard::cpp_17);
    REQUIRE(language_standard::cpp_23 > language_standard::cpp_17);
}

TEST_CASE("version: current_standard", "[vector]")
{
#if defined(TAEL_CPP_STANDARD_17)
    REQUIRE(etl::current_standard == etl::language_standard::cpp_17);
#endif

#if defined(TAEL_CPP_STANDARD_20)
    REQUIRE(etl::current_standard == etl::language_standard::cpp_20);
#endif
}
