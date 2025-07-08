// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.algorithm;
import etl.array;
import etl.functional;
import etl.iterator;
import etl.vector;
#else
    #include <etl/algorithm.hpp>
    #include <etl/array.hpp>
    #include <etl/functional.hpp>
    #include <etl/iterator.hpp>
    #include <etl/vector.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    // empty ranges
    auto e1 = etl::static_vector<T, 4>{};
    auto e2 = etl::static_vector<T, 4>{};
    auto d1 = etl::array<T, 4>{};
    etl::set_difference(begin(e1), end(e1), begin(e2), end(e2), begin(d1));
    CHECK(e1.empty());
    CHECK(e2.empty());
    CHECK(d1[0] == T{0});

    // cppreference.com example #1
    auto const v1 = etl::array{T(1), T(2), T(5), T(5), T(5), T(9)};
    auto const v2 = etl::array{T(2), T(5), T(7)};
    auto d2       = etl::static_vector<T, 4>{};
    etl::set_difference(begin(v1), end(v1), begin(v2), end(v2), etl::back_inserter(d2));
    CHECK(d2[0] == T{1});
    CHECK(d2[1] == T{5});
    CHECK(d2[2] == T{5});
    CHECK(d2[3] == T{9});

    // cppreference.com example #2
    // we want to know which orders "cut" between old and new states:
    etl::array<T, 4> oldOrders{T(1), T(2), T(5), T(9)};
    etl::array<T, 3> newOrders{T(2), T(5), T(7)};
    etl::static_vector<T, 2> cutOrders{};

    etl::set_difference(
        oldOrders.begin(),
        oldOrders.end(),
        newOrders.begin(),
        newOrders.end(),
        etl::back_inserter(cutOrders),
        etl::less()
    );

    CHECK(oldOrders[0] == T{1});
    CHECK(oldOrders[1] == T{2});
    CHECK(oldOrders[2] == T{5});
    CHECK(oldOrders[3] == T{9});

    CHECK(newOrders[0] == T{2});
    CHECK(newOrders[1] == T{5});
    CHECK(newOrders[2] == T{7});

    CHECK(cutOrders[0] == T{1});
    CHECK(cutOrders[1] == T{9});

    return true;
}

static constexpr auto test_all() -> bool
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
