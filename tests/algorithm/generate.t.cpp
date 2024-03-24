// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/iterator.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    auto d = etl::array<T, 4>{};
    etl::generate(begin(d), end(d), [n = T{0}]() mutable { return n++; });
    CHECK(d[0] == 0);
    CHECK(d[1] == 1);
    CHECK(d[2] == 2);
    CHECK(d[3] == 3);

    auto dn  = etl::static_vector<T, 4>{};
    auto rng = []() { return T{42}; };
    etl::generate_n(etl::back_inserter(dn), 4, rng);

    CHECK(dn[0] == T{42});
    CHECK(dn[1] == T{42});
    CHECK(dn[2] == T{42});
    CHECK(dn[3] == T{42});
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
