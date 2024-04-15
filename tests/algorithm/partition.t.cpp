// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/functional.hpp>
#include <etl/iterator.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    auto predicate = [](auto n) { return n < 10; };

    {
        auto empty = etl::static_vector<T, 5>{};
        CHECK(etl::partition(empty.begin(), empty.end(), predicate) == empty.begin());

        auto arr = etl::array{T(11), T(1), T(12), T(13), T(2), T(3), T(4)};
        etl::partition(begin(arr), end(arr), predicate);
        CHECK(arr[0] == 1);
        CHECK(arr[1] == 2);
        CHECK(arr[2] == 3);
        CHECK(arr[3] == 4);
    }

    // empty range
    {
        auto src    = etl::static_vector<T, 5>{};
        auto dTrue  = etl::array<T, 5>{};
        auto dFalse = etl::array<T, 5>{};

        auto res = etl::partition_copy(src.begin(), src.end(), begin(dTrue), begin(dFalse), predicate);
        CHECK(res.first == begin(dTrue));
        CHECK(res.second == begin(dFalse));
    }

    // range
    {
        auto src    = etl::array{T(11), T(1), T(12), T(13), T(2), T(3), T(4)};
        auto dTrue  = etl::static_vector<T, 5>{};
        auto dFalse = etl::static_vector<T, 5>{};

        auto falseIt = etl::back_inserter(dFalse);
        auto trueIt  = etl::back_inserter(dTrue);
        etl::partition_copy(src.begin(), src.end(), trueIt, falseIt, predicate);

        CHECK(dTrue.size() == 4);
        CHECK(etl::all_of(begin(dTrue), end(dTrue), predicate));
        CHECK(dFalse.size() == 3);
        CHECK(etl::all_of(begin(dFalse), end(dFalse), etl::not_fn<predicate>()));
    }

    // empty range
    {
        auto data = etl::static_vector<T, 5>{};
        auto* res = etl::partition_point(data.begin(), data.end(), predicate);
        CHECK(res == end(data));
    }

    // range
    {
        auto data = etl::array{T(1), T(2), T(10), T(11)};
        auto* res = etl::partition_point(data.begin(), data.end(), predicate);
        CHECK(res != end(data));
        CHECK(*res == T(10));
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
