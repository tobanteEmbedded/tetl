/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/expected.hpp"

#include "etl/type_traits.hpp"

#include "helper.hpp"

constexpr auto test() -> bool
{
    using etl::decay_t;
    using etl::is_default_constructible_v;
    using etl::is_same_v;
    using etl::unexpect;
    using etl::unexpect_t;

    assert((is_same_v<unexpect_t, decay_t<decltype(unexpect)>>));
    assert((is_default_constructible_v<unexpect_t>));

    return true;
}

auto main() -> int
{
    assert(test());
    static_assert(test());
    return 0;
}