/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

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

    auto s1 = set_t {};
    assert(s1.size() == 0); // NOLINT
    assert(s1.empty());
    assert(s1.begin() == s1.end());
    assert(etl::as_const(s1).begin() == etl::as_const(s1).end());
    assert(s1.cbegin() == s1.cend());
    assert(s1.max_size() == 8);

    auto s2 = set_t { vec_t {} };
    assert(s2.size() == 0); // NOLINT
    assert(s2.begin() == s2.end());
    assert(s1.begin() != s2.begin());
    assert(s1.end() != s2.end());
    assert(s2.empty());
    assert(s2.max_size() == 8);
    assert(s2.find(T(42)) == etl::end(s2));

    auto r1 = s2.emplace(T(42));
    assert(r1.second);
    assert(s2.size() == 1);
    assert(s2.find(T(42)) == etl::begin(s2));

    auto r2 = s2.insert(T(42));
    assert(not r2.second);
    assert(s2.size() == 1);
    assert(s2.find(T(42)) == etl::begin(s2));

    auto v = etl::array<T, 3> { T(1), T(2), T(3) };
    s2.insert(v.begin(), v.end());
    assert(s2.size() == 4);

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::int8_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::int64_t>());
    assert(test<etl::uint8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::uint64_t>());
    assert(test<float>());
    assert(test<double>());
    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
