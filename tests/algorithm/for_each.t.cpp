// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    etl::array<T, 4> vec{T(1), T(2), T(3), T(4)};

    // Check how often for_each calls the unary function
    auto counter{0};
    auto incrementCounter = [&counter](auto& /*unused*/) { counter += 1; };

    // for_each
    etl::for_each(vec.begin(), vec.end(), incrementCounter);
    CHECK(counter == 4);

    // for_each_n
    counter = 0;
    etl::for_each_n(vec.begin(), 2, incrementCounter);
    CHECK(counter == 2);
    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::uint64_t>());
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
