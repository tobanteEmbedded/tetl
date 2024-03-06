// SPDX-License-Identifier: BSL-1.0

#include <etl/exception.hpp>

#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

constexpr auto test() -> bool
{
    assert((etl::is_default_constructible_v<etl::exception>));
    assert((etl::is_constructible_v<etl::exception, char const*>));
    return true;
}

auto main() -> int
{
    assert(test());
    static_assert(test());
    return 0;
}
