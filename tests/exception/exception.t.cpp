/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/exception.hpp"

#include "etl/type_traits.hpp"

#include "testing.hpp"

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