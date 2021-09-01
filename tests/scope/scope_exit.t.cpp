/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/scope.hpp"

#include "testing.hpp"

auto test() -> bool
{
    {
        auto counter = 0;
        {
            etl::scope_exit e { [&] { counter++; } };
        }
        assert(counter == 1);
    }

    {
        auto counter = 0;
        {
            etl::scope_exit e1 { [&] { counter++; } };
            etl::scope_exit e2 { [&] { counter++; } };
            etl::scope_exit e3 { [&] { counter++; } };
        }
        assert(counter == 3);
    }

    {
        auto counter = 0;
        {
            auto e1 = etl::scope_exit { [&] { counter++; } };
            {
                auto e2 { etl::move(e1) };
                assert(counter == 0);
            }
            assert(counter == 1);
        }
        assert(counter == 1);
    }

    {
        auto counter = 0;
        {
            etl::scope_exit e { [&] { counter++; } };
            e.release();
        }
        assert(counter == 0);
    }

    return true;
}

auto main() -> int
{
    assert(test());
    return 0;
}