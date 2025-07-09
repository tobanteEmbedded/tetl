// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.random;
#else
    #include <etl/random.hpp>
#endif

template <typename URNG, typename RealType>
static constexpr auto test_uniform_real_distribution() -> bool
{
    constexpr auto minimum = RealType(0);
    constexpr auto maximum = RealType(100);

    auto urng = URNG{42};
    auto dist = etl::uniform_real_distribution<RealType>{minimum, maximum};

    for (auto i{0}; i < 100; ++i) {
        auto const x = dist(urng);
        CHECK(x >= minimum);
        CHECK(x < maximum);
    }

    return true;
}

static constexpr auto test() -> bool
{
    CHECK(test_uniform_real_distribution<etl::xorshift32, float>());
    CHECK(test_uniform_real_distribution<etl::xoshiro128plus, float>());
    CHECK(test_uniform_real_distribution<etl::xoshiro128plusplus, float>());
    CHECK(test_uniform_real_distribution<etl::xoshiro128starstar, float>());

#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)
    CHECK(test_uniform_real_distribution<etl::xorshift64, double>());
#endif
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
