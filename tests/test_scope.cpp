/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/scope.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEST_CASE("scope: scope_exit", "[scope]")
{
    SECTION("single")
    {
        auto counter = 0;
        {
            etl::scope_exit e { [&] { counter++; } };
        }
        REQUIRE(counter == 1);
    }

    SECTION("multiple")
    {
        auto counter = 0;
        {
            etl::scope_exit e1 { [&] { counter++; } };
            etl::scope_exit e2 { [&] { counter++; } };
            etl::scope_exit e3 { [&] { counter++; } };
        }
        REQUIRE(counter == 3);
    }

    SECTION("move")
    {
        auto counter = 0;
        {
            auto e1 = etl::scope_exit { [&] { counter++; } };
            {
                auto e2 { etl::move(e1) };
                REQUIRE(counter == 0);
            }
            REQUIRE(counter == 1);
        }
        REQUIRE(counter == 1);
    }

    SECTION("release")
    {
        auto counter = 0;
        {
            etl::scope_exit e { [&] { counter++; } };
            e.release();
        }
        REQUIRE(counter == 0);
    }
}
