/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/ios.hpp"

#include "etl/warning.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEST_CASE("ios: ios_base::openmode", "[ios]")
{
    STATIC_REQUIRE(etl::is_bitmask_type_v<etl::ios_base::openmode>);
}

TEST_CASE("ios: ios_base::fmtflags", "[ios]")
{
    STATIC_REQUIRE(etl::is_bitmask_type_v<etl::ios_base::fmtflags>);
}

TEST_CASE("ios: ios_base::iostate", "[ios]")
{
    STATIC_REQUIRE(etl::is_bitmask_type_v<etl::ios_base::iostate>);
}

TEMPLATE_TEST_CASE("ios: ios_base::basic_stringbuf", "[ios]", char, wchar_t)
{
    using CharT = TestType;

    auto sbuf = etl::basic_stringbuf<CharT, 16> {};
    etl::ignore_unused(sbuf);
    SUCCEED();
}
