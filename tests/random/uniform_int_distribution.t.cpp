// SPDX-License-Identifier: BSL-1.0

#include <etl/random.hpp>

#include "testing/testing.hpp"

template <typename URNG, typename IntType>
constexpr auto test_uniform_int_distribution() -> bool
{
    constexpr auto minimum = IntType(5);
    constexpr auto maximum = IntType(100);

    auto urng = URNG { 42 };
    auto dist = etl::uniform_int_distribution<IntType> { minimum, maximum };

    for (auto i { 0 }; i < 1000; ++i) {
        auto const x = dist(urng);
        assert(x >= minimum);
        assert(x <= maximum);
    }

    return true;
}

constexpr auto test() -> bool
{
    assert(test_uniform_int_distribution<etl::xorshift32, short>());
    assert(test_uniform_int_distribution<etl::xorshift32, int>());
    assert(test_uniform_int_distribution<etl::xorshift32, long>());
    assert(test_uniform_int_distribution<etl::xorshift32, long long>());
    assert(test_uniform_int_distribution<etl::xorshift32, unsigned short>());
    assert(test_uniform_int_distribution<etl::xorshift32, unsigned int>());
    assert(test_uniform_int_distribution<etl::xorshift32, unsigned long>());
    assert(test_uniform_int_distribution<etl::xorshift32, unsigned long long>());

    assert(test_uniform_int_distribution<etl::xorshift64, short>());
    assert(test_uniform_int_distribution<etl::xorshift64, int>());
    assert(test_uniform_int_distribution<etl::xorshift64, long>());
    assert(test_uniform_int_distribution<etl::xorshift64, long long>());
    assert(test_uniform_int_distribution<etl::xorshift64, unsigned short>());
    assert(test_uniform_int_distribution<etl::xorshift64, unsigned int>());
    assert(test_uniform_int_distribution<etl::xorshift64, unsigned long>());
    assert(test_uniform_int_distribution<etl::xorshift64, unsigned long long>());

    assert(test_uniform_int_distribution<etl::xoshiro128plusplus, short>());
    assert(test_uniform_int_distribution<etl::xoshiro128plusplus, int>());
    assert(test_uniform_int_distribution<etl::xoshiro128plusplus, long>());
    assert(test_uniform_int_distribution<etl::xoshiro128plusplus, long long>());
    assert(test_uniform_int_distribution<etl::xoshiro128plusplus, unsigned short>());
    assert(test_uniform_int_distribution<etl::xoshiro128plusplus, unsigned int>());
    assert(test_uniform_int_distribution<etl::xoshiro128plusplus, unsigned long>());
    assert(test_uniform_int_distribution<etl::xoshiro128plusplus, unsigned long long>());

    return true;
}

auto main() -> int
{
    assert(test());
    static_assert(test());
    return 0;
}
