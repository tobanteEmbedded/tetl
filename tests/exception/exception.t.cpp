// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/exception.hpp>
    #include <etl/type_traits.hpp>
#endif

static constexpr auto test() -> bool
{
    CHECK(etl::is_default_constructible_v<etl::exception>);
    CHECK(etl::is_constructible_v<etl::exception, char const*>);
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
