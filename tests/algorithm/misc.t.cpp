// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/iterator.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{

    // cppreference.com example
    {
        etl::array<T, 8> v1{T(1), T(2), T(3), T(4), T(5), T(6), T(7), T(8)};
        etl::array<T, 4> v2{T(5), T(7), T(9), T(10)};
        etl::sort(v1.begin(), v1.end());
        etl::sort(v2.begin(), v2.end());

        etl::static_vector<T, 2> intersection{};
        etl::set_intersection(v1.begin(), v1.end(), v2.begin(), v2.end(), etl::back_inserter(intersection));

        CHECK(intersection[0] == T{5});
        CHECK(intersection[1] == T{7});
    }

    // cppreference.com example
    {
        etl::array<T, 8> v1{T(1), T(2), T(3), T(4), T(5), T(6), T(7), T(8)};
        etl::array<T, 4> v2{T(5), T(7), T(9), T(10)};
        etl::sort(v1.begin(), v1.end());
        etl::sort(v2.begin(), v2.end());

        etl::static_vector<T, 8> symDifference{};
        etl::set_symmetric_difference(v1.begin(), v1.end(), v2.begin(), v2.end(), etl::back_inserter(symDifference));

        CHECK(symDifference[0] == T{1});
        CHECK(symDifference[1] == T{2});
        CHECK(symDifference[2] == T{3});
        CHECK(symDifference[3] == T{4});
        CHECK(symDifference[4] == T{6});
        CHECK(symDifference[5] == T{8});
        CHECK(symDifference[6] == T{9});
        CHECK(symDifference[7] == T{10});
    }

    // cppreference.com example #1
    {
        etl::array<T, 5> v1 = {T(1), T(2), T(3), T(4), T(5)};
        etl::array<T, 5> v2 = {T(3), T(4), T(5), T(6), T(7)};
        etl::static_vector<T, 7> dest;

        etl::set_union(begin(v1), end(v1), begin(v2), end(v2), back_inserter(dest));

        CHECK(dest[0] == T{1});
        CHECK(dest[1] == T{2});
        CHECK(dest[2] == T{3});
        CHECK(dest[3] == T{4});
        CHECK(dest[4] == T{5});
        CHECK(dest[5] == T{6});
        CHECK(dest[6] == T{7});
    }

    // cppreference.com example #1
    {
        etl::array<T, 7> v1 = {T(1), T(2), T(3), T(4), T(5), T(5), T(5)};
        etl::array<T, 5> v2 = {T(3), T(4), T(5), T(6), T(7)};
        etl::static_vector<T, 9> dest;

        etl::set_union(begin(v1), end(v1), begin(v2), end(v2), back_inserter(dest));

        CHECK(dest[0] == T{1});
        CHECK(dest[1] == T{2});
        CHECK(dest[2] == T{3});
        CHECK(dest[3] == T{4});
        CHECK(dest[4] == T{5});
        CHECK(dest[5] == T{5});
        CHECK(dest[6] == T{5});
        CHECK(dest[7] == T{6});
        CHECK(dest[8] == T{7});
    }

    // same data
    {
        auto const a = etl::array{T(1), T(2), T(3)};
        auto const b = etl::array{T(1), T(2), T(3)};
        CHECK(etl::is_permutation(a.begin(), a.end(), begin(b), end(b)));
    }

    // reverse data
    {
        auto const a = etl::array{T(1), T(2), T(3)};
        auto const b = etl::array{T(3), T(2), T(1)};
        CHECK(etl::is_permutation(a.begin(), a.end(), begin(b), end(b)));
    }

    // cppreference.com example
    {
        auto const a = etl::array{T(1), T(2), T(3), T(4), T(5)};
        auto const b = etl::array{T(3), T(5), T(4), T(1), T(2)};
        auto const c = etl::array{T(3), T(5), T(4), T(1), T(1)};
        CHECK(etl::is_permutation(a.begin(), a.end(), begin(b), end(b)));
        CHECK_FALSE(etl::is_permutation(a.begin(), a.end(), begin(c), end(c)));
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
