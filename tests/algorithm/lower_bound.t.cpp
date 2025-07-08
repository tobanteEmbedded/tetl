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
    // empty range
    {
        auto const vec = etl::static_vector<T, 4>{};
        CHECK(etl::lower_bound(begin(vec), end(vec), T(0)) == end(vec));
        CHECK(etl::lower_bound(begin(vec), end(vec), T(0), etl::greater{}) == end(vec));
    }

    // single element
    {
        auto v = etl::static_vector<T, 4>{};
        v.push_back(T(0));
        CHECK(etl::lower_bound(v.begin(), v.end(), T(0)) == v.begin());
        CHECK(etl::lower_bound(v.begin(), v.end(), T(1)) == v.end());
        CHECK(etl::lower_bound(v.begin(), v.end(), T(0), etl::greater{}) == v.begin());
        CHECK(etl::lower_bound(v.begin(), v.end(), T(1), etl::greater{}) == v.begin());

        // reset
        v.clear();
        v.push_back(T(1));
        CHECK(etl::lower_bound(v.begin(), v.end(), T(0)) == v.begin());
        CHECK(etl::lower_bound(v.begin(), v.end(), T(1)) == v.begin());
        CHECK(etl::lower_bound(v.begin(), v.end(), T(0), etl::greater{}) == v.end());
        CHECK(etl::lower_bound(v.begin(), v.end(), T(1), etl::greater{}) == v.begin());
    }

    // multiple elements
    {
        auto const a = etl::array{T(0), T(1), T(2), T(3)};
        CHECK(etl::lower_bound(a.begin(), a.end(), T(0)) == a.begin());
        CHECK(etl::lower_bound(a.begin(), a.end(), T(1)) == a.begin() + 1);
        CHECK(etl::lower_bound(a.begin(), a.end(), T(4)) == a.end());
        CHECK(etl::lower_bound(a.begin(), a.end(), T(0), etl::greater{}) == a.end());
    }

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
