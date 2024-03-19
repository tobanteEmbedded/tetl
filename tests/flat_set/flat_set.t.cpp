// SPDX-License-Identifier: BSL-1.0

#include <etl/flat_set.hpp>

#include <etl/cstdint.hpp>
#include <etl/utility.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    using vec_t = etl::static_vector<T, 8>;
    using set_t = etl::flat_set<T, vec_t>;

    auto s1 = set_t{};
    CHECK(s1.size() == 0); // NOLINT
    CHECK(s1.empty());
    CHECK(s1.begin() == s1.end());
    CHECK(etl::as_const(s1).begin() == etl::as_const(s1).end());
    CHECK(s1.cbegin() == s1.cend());
    CHECK(s1.max_size() == 8);

    auto s2 = set_t{vec_t{}};
    CHECK(s2.size() == 0); // NOLINT
    CHECK(s2.begin() == s2.end());
    CHECK(s1.begin() != s2.begin());
    CHECK(s1.end() != s2.end());
    CHECK(s2.empty());
    CHECK(s2.max_size() == 8);
    CHECK(s2.find(T(42)) == etl::end(s2));

    auto r1 = s2.emplace(T(42));
    CHECK(r1.second);
    CHECK(s2.size() == 1);
    CHECK(s2.find(T(42)) == etl::begin(s2));

    auto r2 = s2.insert(T(42));
    CHECK(not r2.second);
    CHECK(s2.size() == 1);
    CHECK(s2.find(T(42)) == etl::begin(s2));

    auto v = etl::array<T, 3>{T(1), T(2), T(3)};
    s2.insert(v.begin(), v.end());
    CHECK(s2.size() == 4);

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::int64_t>());
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::uint64_t>());
    CHECK(test<float>());
    CHECK(test<double>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
