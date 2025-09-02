// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
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
    auto greater = etl::greater<>();

    // empty range
    {
        auto const d = etl::static_vector<T, 4>{};
        CHECK(etl::upper_bound(begin(d), end(d), T(0)) == end(d));
        CHECK(etl::upper_bound(begin(d), end(d), T(0), greater) == end(d));
    }

    // single element
    {
        auto d = etl::static_vector<T, 4>{};
        d.push_back(T(0));
        CHECK(etl::upper_bound(begin(d), end(d), T(0)) == end(d));
        CHECK(etl::upper_bound(begin(d), end(d), T(1)) == end(d));
        CHECK(etl::upper_bound(begin(d), end(d), T(1), greater) == begin(d));
    }

    // multiple elements
    {
        auto const d = etl::array{T(0), T(1), T(2), T(3)};
        CHECK(etl::upper_bound(begin(d), end(d), T(0)) == begin(d) + 1);
        CHECK(etl::upper_bound(begin(d), end(d), T(1)) == begin(d) + 2);
        CHECK(etl::upper_bound(begin(d), end(d), T(5)) == end(d));
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
