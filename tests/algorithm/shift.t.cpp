// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/iterator.hpp>
#include <etl/vector.hpp>

#include "testing/iterator.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{

    {
        auto d = etl::array{T(1), T(2), T(3), T(4), T(5), T(6)};
        etl::shift_left(begin(d), end(d), 2);
        CHECK(d[0] == T(3));
        CHECK(d[1] == T(4));
        CHECK(d[2] == T(5));
        CHECK(d[3] == T(6));
    }

    {
        auto d = etl::array{T(1), T(2), T(3), T(4), T(5), T(6)};
        etl::shift_left(forward_iter(begin(d)), forward_iter(end(d)), 2);
        CHECK(d[0] == T(3));
        CHECK(d[1] == T(4));
        CHECK(d[2] == T(5));
        CHECK(d[3] == T(6));
    }

    {
        auto const src = etl::array{T(0), T(1), T(2), T(3)};

        auto t0 = src;
        etl::shift_right(begin(t0), end(t0), -1);
        CHECK(t0[0] == T(0));
        CHECK(t0[1] == T(1));
        CHECK(t0[2] == T(2));
        CHECK(t0[3] == T(3));

        auto t00 = src;
        etl::shift_right(begin(t00), end(t00), 4);
        CHECK(t00[0] == T(0));
        CHECK(t00[1] == T(1));
        CHECK(t00[2] == T(2));
        CHECK(t00[3] == T(3));

        auto t1 = src;
        etl::shift_right(begin(t1), end(t1), 1);
        CHECK(t1[1] == T(0));
        CHECK(t1[2] == T(1));
        CHECK(t1[3] == T(2));

        auto t2 = src;
        etl::shift_right(begin(t2), end(t2), 2);
        CHECK(t2[2] == T(0));
        CHECK(t2[3] == T(1));

        auto t3 = src;
        etl::shift_right(begin(t3), end(t3), 3);
        CHECK(t3[3] == T(0));
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

    CHECK(test<char>());
    CHECK(test<char8_t>());
    CHECK(test<char16_t>());
    CHECK(test<char32_t>());
    CHECK(test<wchar_t>());

    CHECK(test<float>());
    CHECK(test<double>());
    CHECK(test<long double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
