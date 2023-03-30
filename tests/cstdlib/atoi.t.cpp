// SPDX-License-Identifier: BSL-1.0
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

#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)
    assert(etl::atoi("99999") == T(99999));
    assert(etl::atoi("999999") == T(999999));
    assert(etl::atoi("123456789") == T(123456789));
#endif

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
