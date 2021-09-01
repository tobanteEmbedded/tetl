/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/numeric.hpp"

#include "testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(etl::abs<T>(0) == T { 0 });
    assert(etl::abs<T>(1) == T { 1 });
    assert(etl::abs<T>(-1) == T { 1 });
    assert(etl::abs<T>(10) == T { 10 });
    assert(etl::abs<T>(-10) == T { 10 });
    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::int8_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::int32_t>());
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
