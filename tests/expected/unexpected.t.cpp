// SPDX-License-Identifier: BSL-1.0

#include <etl/expected.hpp>

#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

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
