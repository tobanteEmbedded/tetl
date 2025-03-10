// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/numeric.hpp>
#include <etl/vector.hpp>

#include "testing/iterator.hpp"
#include "testing/testing.hpp"

template <typename T>
static constexpr auto test() -> bool
{
    auto data            = etl::array{T(1), T(2), T(3), T(4)};
    auto const greater0  = [](T a) { return a > T(0); };
    auto const greater10 = [](T a) { return a > T(10); };
    auto const less10    = [](T a) { return a < T(10); };

    CHECK(etl::all_of(data.begin(), data.end(), greater0));
    CHECK_FALSE(etl::all_of(data.begin(), data.end(), greater10));
    CHECK(etl::all_of(InIter(data.begin()), InIter(data.end()), greater0));

    CHECK(etl::any_of(data.begin(), data.end(), greater0));
    CHECK_FALSE(etl::any_of(data.begin(), data.end(), greater10));
    CHECK(etl::any_of(InIter(data.begin()), InIter(data.end()), greater0));

    CHECK(etl::none_of(data.begin(), data.end(), greater10));
    CHECK_FALSE(etl::none_of(data.begin(), data.end(), less10));
    CHECK(etl::none_of(InIter(data.begin()), InIter(data.end()), greater10));

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
