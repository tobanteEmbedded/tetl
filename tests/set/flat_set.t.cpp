/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/set.hpp"

#include "etl/cstdint.hpp"
#include "etl/vector.hpp"

#include "testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    using vec_t = etl::static_vector<T, 8>;
    using set_t = etl::flat_set<T, vec_t>;

    auto s1 = set_t {};
    assert(s1.size() == 0); // NOLINT
    assert(s1.empty());
    assert(s1.max_size() == 8);

    auto s2 = set_t { vec_t {} };
    assert(s2.size() == 0); // NOLINT
    assert(s2.empty());
    assert(s2.max_size() == 8);
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