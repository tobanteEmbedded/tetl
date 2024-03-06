// SPDX-License-Identifier: BSL-1.0

#include <etl/scope.hpp>

#include "testing/testing.hpp"

static auto test() -> bool
{
    {
        auto counter = 0;
        {
            etl::scope_exit e {[&] { counter++; }};
        }
        assert(counter == 1);
    }

    {
        auto counter = 0;
        {
            etl::scope_exit e1 {[&] { counter++; }};
            etl::scope_exit e2 {[&] { counter++; }};
            etl::scope_exit e3 {[&] { counter++; }};
        }
        assert(counter == 3);
    }

    {
        auto counter = 0;
        {
            auto e1 = etl::scope_exit {[&] { counter++; }};
            {
                auto e2 {etl::move(e1)};
                assert(counter == 0);
            }
            assert(counter == 1);
        }
        assert(counter == 1);
    }

    {
        auto counter = 0;
        {
            etl::scope_exit e {[&] { counter++; }};
            e.release();
        }
        assert(counter == 0);
    }

    return true;
}

auto main() -> int
{
    assert(test());
    // static_assert(test());
    return 0;
}
