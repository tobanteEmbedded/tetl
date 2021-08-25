/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "catch2/catch_template_test_macros.hpp"

#include "etl/experimental/hardware/mcp23017/mcp23017.hpp"

using namespace etl::experimental::hardware;

struct driver {
};

TEST_CASE("experimental/mcp23017: init", "[hardware][experimental]")
{
    mcp23017::device<driver> device {};
    REQUIRE(device.init() == true);
}