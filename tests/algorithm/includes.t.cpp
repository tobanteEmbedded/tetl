// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.algorithm;
import etl.array;
import etl.iterator;
import etl.cctype;
#else
    #include <etl/algorithm.hpp>
    #include <etl/array.hpp>
    #include <etl/cctype.hpp>
    #include <etl/iterator.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{

    {
        auto const v1 = etl::array{'a', 'b', 'c', 'f', 'h', 'x'};
        auto const v2 = etl::array{'a', 'b', 'c'};
        auto const v3 = etl::array{'a', 'c'};
        auto const v4 = etl::array{'a', 'a', 'b'};
        auto const v5 = etl::array{'g'};
        auto const v6 = etl::array{'a', 'c', 'g'};
        auto const v7 = etl::array{'A', 'B', 'C'};

        auto noCase = [](char a, char b) { return etl::tolower(a) < etl::tolower(b); };

        CHECK(etl::includes(begin(v1), end(v1), v2.begin(), v2.end()));
        CHECK(etl::includes(begin(v1), end(v1), v3.begin(), v3.end()));
        CHECK(etl::includes(begin(v1), end(v1), v7.begin(), v7.end(), noCase));

        CHECK_FALSE(etl::includes(begin(v1), end(v1), v4.begin(), v4.end()));
        CHECK_FALSE(etl::includes(begin(v1), end(v1), v5.begin(), v5.end()));
        CHECK_FALSE(etl::includes(begin(v1), end(v1), v6.begin(), v6.end()));
    }

    {
        auto const v1 = etl::array{T(1), T(2), T(3), T(6), T(8), T(24)};
        auto const v2 = etl::array{T(1), T(2), T(3)};
        auto const v3 = etl::array{T(1), T(3)};
        auto const v4 = etl::array{T(1), T(1), T(2)};
        auto const v5 = etl::array{T(7)};
        auto const v6 = etl::array{T(1), T(3), T(7)};

        CHECK(etl::includes(begin(v1), end(v1), v2.begin(), v2.end()));
        CHECK(etl::includes(begin(v1), end(v1), v3.begin(), v3.end()));

        CHECK_FALSE(etl::includes(begin(v1), end(v1), v4.begin(), v4.end()));
        CHECK_FALSE(etl::includes(begin(v1), end(v1), v5.begin(), v5.end()));
        CHECK_FALSE(etl::includes(begin(v1), end(v1), v6.begin(), v6.end()));
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
