// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
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
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::uint64_t>());
    CHECK(test<etl::int64_t>());
    CHECK(test<float>());
    CHECK(test<double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
