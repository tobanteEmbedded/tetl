// SPDX-License-Identifier: BSL-1.0

#include <etl/string.hpp>

#include <etl/string_view.hpp>

#include "testing/testing.hpp"

constexpr auto test() -> bool
{
    using namespace etl::string_view_literals;

    auto foo    = TETL_STRING_C("foo");
    auto barbaz = TETL_STRING_C("barbaz");
    ASSERT(foo.size() == 3);
    ASSERT(foo == "foo"_sv);

    ASSERT(barbaz.size() == 6);
    ASSERT(barbaz == "barbaz"_sv);

    ASSERT(foo != barbaz);
    ASSERT(foo != "barbaz"_sv);

    return true;
}

auto main() -> int
{
    ASSERT(test());
    static_assert(test());
    return 0;
}
