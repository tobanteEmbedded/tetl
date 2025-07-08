// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.algorithm;
import etl.array;
import etl.numeric;
import etl.iterator;
#else
    #include <etl/algorithm.hpp>
    #include <etl/array.hpp>
    #include <etl/iterator.hpp>
    #include <etl/numeric.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    // reverse
    {
        // fill
        auto data = etl::array<T, 4>{};
        etl::iota(data.begin(), data.end(), T{0});
        CHECK(data == etl::array{T(0), T(1), T(2), T(3)});

        // empty range
        etl::reverse(data.begin(), data.begin());
        CHECK(data == etl::array{T(0), T(1), T(2), T(3)});

        // full range
        etl::reverse(data.begin(), data.end());
        CHECK(data == etl::array{T(3), T(2), T(1), T(0)});
    }

    // reverse_copy
    {
        auto source = etl::array<T, 4>{};
        etl::iota(source.begin(), source.end(), T{0});

        auto destination = etl::array<T, 4>{};
        etl::reverse_copy(source.begin(), source.end(), destination.begin());
        CHECK(destination == etl::array{T(3), T(2), T(1), T(0)});
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
