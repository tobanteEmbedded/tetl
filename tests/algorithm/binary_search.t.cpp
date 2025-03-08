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
    // epmty range
    auto const e = etl::static_vector<T, 4>{};
    CHECK_FALSE(etl::binary_search(begin(e), end(e), T(0)));
    CHECK_FALSE(etl::binary_search(FwdIter(begin(e)), FwdIter(end(e)), T(0)));

    // range
    auto const data = etl::array{T(0), T(1), T(2)};
    CHECK(etl::binary_search(data.begin(), data.end(), T(0)));
    CHECK(etl::binary_search(data.begin(), data.end(), T(1)));
    CHECK(etl::binary_search(data.begin(), data.end(), T(2)));
    CHECK_FALSE(etl::binary_search(data.begin(), data.end(), T(3)));
    CHECK_FALSE(etl::binary_search(data.begin(), data.end(), T(4)));

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
