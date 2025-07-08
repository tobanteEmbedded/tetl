// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.cstdint;
#else
    #include <etl/cstdint.hpp>
#endif

static constexpr auto test() -> bool
{
    CHECK(sizeof(etl::int8_t) == 1);
    CHECK(sizeof(etl::int16_t) == 2);
    CHECK(sizeof(etl::int32_t) == 4);
    CHECK(sizeof(etl::int64_t) == 8);
    CHECK(sizeof(etl::uint8_t) == 1);
    CHECK(sizeof(etl::uint16_t) == 2);
    CHECK(sizeof(etl::uint32_t) == 4);
    CHECK(sizeof(etl::uint64_t) == 8);
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
