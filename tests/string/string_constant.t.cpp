// SPDX-License-Identifier: BSL-1.0

#include <etl/string.hpp>

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.string_view;
#else
    #include <etl/string_view.hpp>
#endif

static constexpr auto test() -> bool
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
    STATIC_CHECK(test());
    return 0;
}
