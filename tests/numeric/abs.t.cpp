// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/cstdint.hpp>
    #include <etl/numeric.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    CHECK(etl::abs<T>(0) == T{0});
    CHECK(etl::abs<T>(1) == T{1});
    CHECK(etl::abs<T>(-1) == T{1});
    CHECK(etl::abs<T>(10) == T{10});
    CHECK(etl::abs<T>(-10) == T{10});
    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::int64_t>());
    CHECK(test<float>());
    CHECK(test<double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
