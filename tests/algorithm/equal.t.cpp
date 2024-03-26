// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/functional.hpp>

#include "testing/iterator.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    auto lhs = etl::array<T, 2>{T{0}, T{1}};
    auto rhs = etl::array<T, 2>{T{0}, T{1}};
    auto cmp = etl::not_equal_to{};

    CHECK(etl::equal(lhs.begin(), lhs.end(), rhs.begin()));
    CHECK(etl::equal(input_iter(lhs.begin()), input_iter(lhs.end()), input_iter(rhs.begin())));
    CHECK(etl::equal(forward_iter(lhs.begin()), forward_iter(lhs.end()), forward_iter(rhs.begin())));

    CHECK_FALSE(etl::equal(lhs.begin(), lhs.end(), rhs.begin(), cmp));
    CHECK_FALSE(etl::equal(input_iter(lhs.begin()), input_iter(lhs.end()), input_iter(rhs.begin()), cmp));

    CHECK(etl::equal(lhs.begin(), lhs.end(), rhs.begin(), rhs.end()));
    CHECK_FALSE(etl::equal(lhs.begin(), lhs.end(), rhs.begin(), rhs.end(), cmp));

    auto small = etl::array{T(1)};
    CHECK_FALSE(etl::equal(lhs.begin(), lhs.end(), small.begin(), small.end(), cmp));

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
