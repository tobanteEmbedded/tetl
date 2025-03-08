// SPDX-License-Identifier: BSL-1.0

#include <etl/scope.hpp>

#include "testing/testing.hpp"

static constexpr auto test() -> bool
{
    {
        auto counter = 0;
        {
            etl::scope_exit e{[&] { counter++; }};
        }
        CHECK(counter == 1);
    }

    {
        auto counter = 0;
        {
            etl::scope_exit e1{[&] { counter++; }};
            etl::scope_exit e2{[&] { counter++; }};
            etl::scope_exit e3{[&] { counter++; }};
        }
        CHECK(counter == 3);
    }

    {
        auto counter = 0;
        {
            auto e1 = etl::scope_exit{[&] { counter++; }};
            {
                auto e2{etl::move(e1)};
                CHECK(counter == 0);
            }
            CHECK(counter == 1);
        }
        CHECK(counter == 1);
    }

    {
        auto counter = 0;
        {
            etl::scope_exit e{[&] { counter++; }};
            e.release();
        }
        CHECK(counter == 0);
    }

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
