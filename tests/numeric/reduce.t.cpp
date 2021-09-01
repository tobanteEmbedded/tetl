/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/numeric.hpp"

#include "etl/array.hpp"

#include "testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    auto vec = etl::array { T(1), T(2), T(3), T(4) };
    assert(etl::reduce(vec.begin(), vec.end()) == T(10));
    assert(etl::reduce(vec.begin(), vec.end(), T { 0 }) == T(10));

    auto func = [](T a, T b) { return static_cast<T>(a + (b * T { 2 })); };
    assert(etl::reduce(vec.begin(), vec.end(), T { 0 }, func) == T(20));
    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::int8_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::int64_t>());
    assert(test<etl::uint8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::uint64_t>());
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
