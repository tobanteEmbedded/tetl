// SPDX-License-Identifier: BSL-1.0

#include <etl/string.hpp>

#include <etl/string_view.hpp>

#include "testing/testing.hpp"

constexpr auto test() -> bool
{
    using namespace etl::string_view_literals;

    auto foo    = TETL_STRING_C("foo");
    auto barbaz = TETL_STRING_C("barbaz");
    CHECK(foo.size() == 3);
    CHECK(foo == "foo"_sv);

    CHECK(barbaz.size() == 6);
    CHECK(barbaz == "barbaz"_sv);

    CHECK(foo != barbaz);
    CHECK(foo != "barbaz"_sv);

    return true;
}

auto main() -> int
{
    CHECK(test());
    static_assert(test());
    return 0;
}
