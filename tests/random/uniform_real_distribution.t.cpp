/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include <etl/random.hpp>

#include "testing/testing.hpp"

template <typename URNG, typename RealType>
constexpr auto test_uniform_real_distribution() -> bool
{
    constexpr auto minimum = RealType(0);
    constexpr auto maximum = RealType(100);

    auto urng = URNG { 42 };
    auto dist = etl::uniform_real_distribution<RealType> { minimum, maximum };

    for (auto i { 0 }; i < 1000; ++i) {
        auto const x = dist(urng);
        assert(x >= minimum);
        assert(x < maximum);
    }

    return true;
}

constexpr auto test() -> bool
{
    assert(test_uniform_real_distribution<etl::xorshift32, float>());
    assert(test_uniform_real_distribution<etl::xoshiro128plus, float>());
    assert(test_uniform_real_distribution<etl::xoshiro128plusplus, float>());
    assert(test_uniform_real_distribution<etl::xoshiro128starstar, float>());

    assert(test_uniform_real_distribution<etl::xorshift64, double>());
    return true;
}

auto main() -> int
{
    assert(test());
    static_assert(test());
    return 0;
}
