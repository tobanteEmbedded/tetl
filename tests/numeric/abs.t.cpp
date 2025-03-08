// SPDX-License-Identifier: BSL-1.0

#include <etl/numeric.hpp>

#include <etl/cstdint.hpp>

#include "testing/testing.hpp"

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
