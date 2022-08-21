/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/algorithm.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    etl::array<T, 4> vec { T(1), T(2), T(3), T(4) };

    // Check how often for_each calls the unary function
    auto counter { 0 };
    auto incrementCounter = [&counter](auto& /*unused*/) { counter += 1; };

    // for_each
    etl::for_each(vec.begin(), vec.end(), incrementCounter);
    assert(counter == 4);

    // for_each_n
    counter = 0;
    etl::for_each_n(vec.begin(), 2, incrementCounter);
    assert(counter == 2);
    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::uint8_t>());
    assert(test<etl::int8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::uint64_t>());
    assert(test<etl::int64_t>());
    assert(test<float>());
    assert(test<double>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
