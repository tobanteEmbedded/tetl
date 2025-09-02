// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/random.hpp>
#endif

template <typename URNG, typename IntType>
static constexpr auto test_uniform_int_distribution() -> bool
{
    constexpr auto minimum = IntType(5);
    constexpr auto maximum = IntType(100);

    auto urng = URNG{42};
    auto dist = etl::uniform_int_distribution<IntType>{minimum, maximum};

    for (auto i{0}; i < 100; ++i) {
        auto const x = dist(urng);
        CHECK(x >= minimum);
        CHECK(x <= maximum);
    }

    return true;
}

static constexpr auto test() -> bool
{
    CHECK(test_uniform_int_distribution<etl::xorshift32, short>());
    CHECK(test_uniform_int_distribution<etl::xorshift32, int>());
    CHECK(test_uniform_int_distribution<etl::xorshift32, long>());
    CHECK(test_uniform_int_distribution<etl::xorshift32, long long>());
    CHECK(test_uniform_int_distribution<etl::xorshift32, unsigned short>());
    CHECK(test_uniform_int_distribution<etl::xorshift32, unsigned int>());
    CHECK(test_uniform_int_distribution<etl::xorshift32, unsigned long>());
    CHECK(test_uniform_int_distribution<etl::xorshift32, unsigned long long>());

    CHECK(test_uniform_int_distribution<etl::xorshift64, short>());
    CHECK(test_uniform_int_distribution<etl::xorshift64, int>());
    CHECK(test_uniform_int_distribution<etl::xorshift64, long>());
    CHECK(test_uniform_int_distribution<etl::xorshift64, long long>());
    CHECK(test_uniform_int_distribution<etl::xorshift64, unsigned short>());
    CHECK(test_uniform_int_distribution<etl::xorshift64, unsigned int>());
    CHECK(test_uniform_int_distribution<etl::xorshift64, unsigned long>());
    CHECK(test_uniform_int_distribution<etl::xorshift64, unsigned long long>());

    CHECK(test_uniform_int_distribution<etl::xoshiro128plusplus, short>());
    CHECK(test_uniform_int_distribution<etl::xoshiro128plusplus, int>());
    CHECK(test_uniform_int_distribution<etl::xoshiro128plusplus, long>());
    CHECK(test_uniform_int_distribution<etl::xoshiro128plusplus, long long>());
    CHECK(test_uniform_int_distribution<etl::xoshiro128plusplus, unsigned short>());
    CHECK(test_uniform_int_distribution<etl::xoshiro128plusplus, unsigned int>());
    CHECK(test_uniform_int_distribution<etl::xoshiro128plusplus, unsigned long>());
    CHECK(test_uniform_int_distribution<etl::xoshiro128plusplus, unsigned long long>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
