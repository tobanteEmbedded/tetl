// SPDX-License-Identifier: BSL-1.0

#include <etl/utility.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    {
        CHECK(etl::cmp_equal(0, T{0}));
        CHECK_FALSE(etl::cmp_equal(-1, T{0}));
        CHECK_FALSE(etl::cmp_equal(T{0}, -1));

        CHECK(etl::cmp_equal(T{0}, T{0}));
        CHECK(etl::cmp_equal(T{1}, T{1}));
        CHECK(etl::cmp_equal(T{42}, T{42}));

        CHECK_FALSE(etl::cmp_equal(T{0}, T{1}));
        CHECK_FALSE(etl::cmp_equal(T{1}, T{0}));
        CHECK_FALSE(etl::cmp_equal(T{42}, T{43}));
    }

    {
        CHECK(etl::cmp_not_equal(-1, T{0}));
        CHECK(etl::cmp_not_equal(T{0}, -1));
        CHECK_FALSE(etl::cmp_not_equal(0, T{0}));

        CHECK_FALSE(etl::cmp_not_equal(T{0}, T{0}));
        CHECK_FALSE(etl::cmp_not_equal(T{1}, T{1}));
        CHECK_FALSE(etl::cmp_not_equal(T{42}, T{42}));

        CHECK(etl::cmp_not_equal(T{0}, T{1}));
        CHECK(etl::cmp_not_equal(T{1}, T{0}));
        CHECK(etl::cmp_not_equal(T{42}, T{43}));
    }

    {
        CHECK(etl::cmp_less(-1, T{0}));
        CHECK_FALSE(etl::cmp_less(0, T{0}));

        CHECK(etl::cmp_less(T{0}, T{1}));
        CHECK(etl::cmp_less(T{1}, T{2}));
        CHECK(etl::cmp_less(T{42}, T{43}));

        CHECK_FALSE(etl::cmp_less(T{2}, T{1}));
        CHECK_FALSE(etl::cmp_less(T{1}, T{0}));
        CHECK_FALSE(etl::cmp_less(T{44}, T{43}));
    }

    {
        CHECK_FALSE(etl::cmp_greater(-1, T{0}));
        CHECK_FALSE(etl::cmp_greater(0, T{0}));

        CHECK_FALSE(etl::cmp_greater(T{0}, T{1}));
        CHECK_FALSE(etl::cmp_greater(T{1}, T{2}));
        CHECK_FALSE(etl::cmp_greater(T{42}, T{43}));

        CHECK(etl::cmp_greater(T{2}, T{1}));
        CHECK(etl::cmp_greater(T{1}, T{0}));
        CHECK(etl::cmp_greater(T{44}, T{43}));
    }

    {
        CHECK(etl::cmp_less_equal(-1, T{0}));
        CHECK(etl::cmp_less_equal(0, T{0}));

        CHECK(etl::cmp_less_equal(T{0}, T{1}));
        CHECK(etl::cmp_less_equal(T{1}, T{1}));
        CHECK(etl::cmp_less_equal(T{1}, T{2}));
        CHECK(etl::cmp_less_equal(T{42}, T{43}));

        CHECK_FALSE(etl::cmp_less_equal(T{2}, T{1}));
        CHECK_FALSE(etl::cmp_less_equal(T{1}, T{0}));
        CHECK_FALSE(etl::cmp_less_equal(T{44}, T{43}));
    }

    {
        CHECK_FALSE(etl::cmp_greater_equal(-1, T{0}));
        CHECK(etl::cmp_greater_equal(0, T{0}));
        CHECK(etl::cmp_greater_equal(T{0}, 0));

        CHECK_FALSE(etl::cmp_greater_equal(T{0}, T{1}));
        CHECK_FALSE(etl::cmp_greater_equal(T{1}, T{2}));
        CHECK_FALSE(etl::cmp_greater_equal(T{42}, T{43}));

        CHECK(etl::cmp_greater_equal(T{2}, T{2}));
        CHECK(etl::cmp_greater_equal(T{2}, T{1}));
        CHECK(etl::cmp_greater_equal(T{1}, T{0}));
        CHECK(etl::cmp_greater_equal(T{44}, T{43}));
    }

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<signed char>());
    CHECK(test<signed short>());
    CHECK(test<signed int>());
    CHECK(test<signed long>());
    CHECK(test<signed long long>());

    CHECK(test<unsigned char>());
    CHECK(test<unsigned short>());
    CHECK(test<unsigned int>());
    CHECK(test<unsigned long>());
    CHECK(test<unsigned long long>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
