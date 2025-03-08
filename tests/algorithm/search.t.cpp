// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/functional.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
static constexpr auto test() -> bool
{
    // find match
    {
        auto src  = etl::array{T(0), T(0), T(0), T(1), T(2), T(3)};
        auto dest = etl::array{T(1), T(2), T(3)};
        auto* res = etl::search(src.begin(), src.end(), begin(dest), end(dest));
        CHECK(*res == T(1));
    }

    // no match
    {
        auto src  = etl::array{T(0), T(0), T(0), T(0), T(2), T(3)};
        auto dest = etl::array{T(1), T(2), T(3)};
        auto* res = etl::search(src.begin(), src.end(), begin(dest), end(dest));
        CHECK(res == end(src));
    }

    // match range empty
    {
        auto src  = etl::array{T(0), T(0), T(0), T(0), T(2), T(3)};
        auto dest = etl::static_vector<T, 0>{};
        auto* res = etl::search(src.begin(), src.end(), begin(dest), end(dest));
        CHECK(res == begin(src));
    }

    // searcher
    {

        auto src = etl::array{T(0), T(0), T(0), T(1), T(2), T(3)};

        auto t1 = etl::array{T(1), T(2), T(3)};
        auto s1 = etl::default_searcher(t1.begin(), t1.end());
        CHECK(*etl::search(src.begin(), src.end(), s1) == T(1));

        auto t2 = etl::static_vector<T, 0>{};
        auto s2 = etl::default_searcher(t2.begin(), t2.end());
        CHECK(etl::search(src.begin(), src.end(), s2) == begin(src));

        CHECK(etl::search(static_cast<T*>(nullptr), static_cast<T*>(nullptr), s2) == static_cast<T*>(nullptr));
    }

    // empty range
    {
        auto src  = etl::static_vector<T, 2>{};
        auto* res = etl::search_n(src.begin(), src.end(), 3, T(0));
        CHECK(res == end(src));
    }

    // zero or negative count
    {
        auto src = etl::array{T(0), T(0), T(0), T(1), T(2), T(3)};
        CHECK(etl::search_n(src.begin(), src.end(), 0, T(0)) == begin(src));
    }

    // no match
    {
        auto src  = etl::array{T(0), T(0), T(0), T(1), T(2), T(3)};
        auto* res = etl::search_n(src.begin(), src.end(), 3, T(42));
        CHECK(res == end(src));
    }

    // find match
    {
        auto src  = etl::array{T(0), T(0), T(0), T(1), T(2), T(3)};
        auto* res = etl::search_n(src.begin(), src.end(), 3, T(0));
        CHECK(res == begin(src));
        CHECK(*res == T(0));
    }

    // cppreference.com example
    {
        etl::array<T, 12> v{1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4};
        etl::array<T, 3> t1{1, 2, 3};

        auto* result = etl::find_end(v.begin(), v.end(), begin(t1), end(t1));
        CHECK(etl::distance(v.begin(), result) == 8);

        etl::array<T, 3> t2{4, 5, 6};
        result = etl::find_end(v.begin(), v.end(), begin(t2), end(t2));
        CHECK(result == v.end());
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
