// SPDX-License-Identifier: BSL-1.0

#include "testing/iterator.hpp"
#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/algorithm.hpp>
    #include <etl/array.hpp>
    #include <etl/iterator.hpp>
    #include <etl/vector.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    // empty rhs
    {
        auto lhs = etl::static_vector<T, 1>{};
        auto rhs = etl::array{T(1), T(2), T(3), T(4), T(5), T(6), T(7), T(8)};
        auto out = etl::array<T, 8>{};
        etl::set_symmetric_difference(FwdIter(lhs.begin()), FwdIter(lhs.end()), rhs.begin(), rhs.end(), out.begin());
        CHECK(out == etl::array{T(1), T(2), T(3), T(4), T(5), T(6), T(7), T(8)});
    }

    // empty rhs
    {
        auto lhs = etl::array{T(1), T(2), T(3), T(4), T(5), T(6), T(7), T(8)};
        auto rhs = etl::static_vector<T, 1>{};
        auto out = etl::array<T, 8>{};
        etl::set_symmetric_difference(FwdIter(lhs.begin()), FwdIter(lhs.end()), rhs.begin(), rhs.end(), out.begin());
        CHECK(out == etl::array{T(1), T(2), T(3), T(4), T(5), T(6), T(7), T(8)});
    }

    // cppreference.com example
    {
        auto lhs = etl::array{T(5), T(7), T(9), T(10)};
        auto rhs = etl::array{T(1), T(2), T(3), T(4), T(5), T(6), T(7), T(8)};
        auto out = etl::array<T, 8>{};
        etl::set_symmetric_difference(FwdIter(lhs.begin()), FwdIter(lhs.end()), rhs.begin(), rhs.end(), out.begin());
        CHECK(out == etl::array{T(1), T(2), T(3), T(4), T(6), T(8), T(9), T(10)});
    }

    // cppreference.com example
    {
        auto lhs = etl::array{T(1), T(2), T(3), T(4), T(5), T(6), T(7), T(8)};
        auto rhs = etl::array{T(5), T(7), T(9), T(10)};
        auto out = etl::array<T, 8>{};
        etl::set_symmetric_difference(FwdIter(lhs.begin()), FwdIter(lhs.end()), rhs.begin(), rhs.end(), out.begin());
        CHECK(out == etl::array{T(1), T(2), T(3), T(4), T(6), T(8), T(9), T(10)});
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
