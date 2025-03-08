// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/functional.hpp>
#include <etl/iterator.hpp>
#include <etl/string.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
static constexpr auto test() -> bool
{
    etl::array<T, 4> a{T(2), T(2), T(2), T(2)};
    auto func = [](auto v) { return static_cast<T>(v * 2); };
    etl::transform(a.begin(), a.end(), a.begin(), func);
    CHECK(etl::all_of(a.begin(), a.end(), [](auto v) { return v == 4; }));

    etl::inplace_string<32> str("hello");
    etl::static_vector<T, 8> vec{};
    auto const identity = [](auto c) -> T { return static_cast<T>(c); };
    etl::transform(begin(str), end(str), etl::back_inserter(vec), identity);

    CHECK(vec[0] == static_cast<T>('h'));
    CHECK(vec[1] == static_cast<T>('e'));
    CHECK(vec[2] == static_cast<T>('l'));
    CHECK(vec[3] == static_cast<T>('l'));
    CHECK(vec[4] == static_cast<T>('o'));

    etl::transform(cbegin(vec), cend(vec), cbegin(vec), begin(vec), etl::plus<T>{});

    CHECK(vec[0] == static_cast<T>('h' * 2));
    CHECK(vec[1] == static_cast<T>('e' * 2));
    CHECK(vec[2] == static_cast<T>('l' * 2));
    CHECK(vec[3] == static_cast<T>('l' * 2));
    CHECK(vec[4] == static_cast<T>('o' * 2));

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
