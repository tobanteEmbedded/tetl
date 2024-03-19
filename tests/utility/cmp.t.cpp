// SPDX-License-Identifier: BSL-1.0

#include <etl/utility.hpp>

#include <etl/cstdint.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    {
        assert((etl::cmp_equal(0, T{0})));
        assert(!(etl::cmp_equal(-1, T{0})));

        assert((etl::cmp_equal(T{0}, T{0})));
        assert((etl::cmp_equal(T{1}, T{1})));
        assert((etl::cmp_equal(T{42}, T{42})));

        assert(!(etl::cmp_equal(T{0}, T{1})));
        assert(!(etl::cmp_equal(T{1}, T{0})));
        assert(!(etl::cmp_equal(T{42}, T{43})));
    }

    {
        assert((etl::cmp_not_equal(-1, T{0})));
        assert(!(etl::cmp_not_equal(0, T{0})));

        assert(!(etl::cmp_not_equal(T{0}, T{0})));
        assert(!(etl::cmp_not_equal(T{1}, T{1})));
        assert(!(etl::cmp_not_equal(T{42}, T{42})));

        assert((etl::cmp_not_equal(T{0}, T{1})));
        assert((etl::cmp_not_equal(T{1}, T{0})));
        assert((etl::cmp_not_equal(T{42}, T{43})));
    }

    {
        assert((etl::cmp_less(-1, T{0})));
        assert(!(etl::cmp_less(0, T{0})));

        assert((etl::cmp_less(T{0}, T{1})));
        assert((etl::cmp_less(T{1}, T{2})));
        assert((etl::cmp_less(T{42}, T{43})));

        assert(!(etl::cmp_less(T{2}, T{1})));
        assert(!(etl::cmp_less(T{1}, T{0})));
        assert(!(etl::cmp_less(T{44}, T{43})));
    }

    {
        assert(!(etl::cmp_greater(-1, T{0})));
        assert(!(etl::cmp_greater(0, T{0})));

        assert(!(etl::cmp_greater(T{0}, T{1})));
        assert(!(etl::cmp_greater(T{1}, T{2})));
        assert(!(etl::cmp_greater(T{42}, T{43})));

        assert((etl::cmp_greater(T{2}, T{1})));
        assert((etl::cmp_greater(T{1}, T{0})));
        assert((etl::cmp_greater(T{44}, T{43})));
    }

    {
        assert((etl::cmp_less_equal(-1, T{0})));
        assert((etl::cmp_less_equal(0, T{0})));

        assert((etl::cmp_less_equal(T{0}, T{1})));
        assert((etl::cmp_less_equal(T{1}, T{1})));
        assert((etl::cmp_less_equal(T{1}, T{2})));
        assert((etl::cmp_less_equal(T{42}, T{43})));

        assert(!(etl::cmp_less_equal(T{2}, T{1})));
        assert(!(etl::cmp_less_equal(T{1}, T{0})));
        assert(!(etl::cmp_less_equal(T{44}, T{43})));
    }

    {
        assert(!(etl::cmp_greater_equal(-1, T{0})));
        assert((etl::cmp_greater_equal(0, T{0})));
        assert((etl::cmp_greater_equal(T{0}, 0)));

        assert(!(etl::cmp_greater_equal(T{0}, T{1})));
        assert(!(etl::cmp_greater_equal(T{1}, T{2})));
        assert(!(etl::cmp_greater_equal(T{42}, T{43})));

        assert((etl::cmp_greater_equal(T{2}, T{2})));
        assert((etl::cmp_greater_equal(T{2}, T{1})));
        assert((etl::cmp_greater_equal(T{1}, T{0})));
        assert((etl::cmp_greater_equal(T{44}, T{43})));
    }

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
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
