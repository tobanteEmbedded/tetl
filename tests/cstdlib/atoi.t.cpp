/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/cstdlib.hpp"

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(etl::atoi("0") == T(0));
    assert(etl::atoi("10") == T(10));
    assert(etl::atoi("99") == T(99));
    assert(etl::atoi("143") == T(143));
    assert(etl::atoi("999") == T(999));
    assert(etl::atoi("1111") == T(1111));
    assert(etl::atoi("99999") == T(99999));
    assert(etl::atoi("999999") == T(999999));
    assert(etl::atoi("123456789") == T(123456789));

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<int>());
    assert(test<long>());
    assert(test<long long>());
    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}