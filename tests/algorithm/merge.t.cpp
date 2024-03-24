// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/iterator.hpp>
#include <etl/numeric.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    // no overlap
    {
        auto a = etl::array{T(0), T(0), T(0)};
        auto b = etl::array{T(1), T(1), T(1)};
        CHECK(etl::is_sorted(begin(a), end(a)));
        CHECK(etl::is_sorted(begin(b), end(b)));

        auto r = etl::static_vector<T, a.size() + b.size()>{};
        etl::merge(begin(a), end(a), begin(b), end(b), etl::back_inserter(r));
        CHECK(r.size() == 6);
        CHECK(etl::is_sorted(begin(r), end(r)));
    }

    // with overlap
    {
        auto a = etl::array{T(0), T(1), T(2)};
        auto b = etl::array{T(1), T(2), T(3)};
        CHECK(etl::is_sorted(begin(a), end(a)));
        CHECK(etl::is_sorted(begin(b), end(b)));

        auto r = etl::static_vector<T, a.size() + b.size()>{};
        etl::merge(begin(a), end(a), begin(b), end(b), etl::back_inserter(r));
        CHECK(r.size() == 6);
        CHECK(etl::is_sorted(begin(r), end(r)));
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
