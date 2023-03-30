// SPDX-License-Identifier: BSL-1.0

#include "etl/algorithm.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/functional.hpp"

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    auto lhs = etl::array<T, 2> { T { 0 }, T { 1 } };
    auto rhs = etl::array<T, 2> { T { 0 }, T { 1 } };
    auto cmp = etl::not_equal_to<> {};

    assert(etl::equal(begin(lhs), end(lhs), begin(rhs)));
    assert(!etl::equal(begin(lhs), end(lhs), begin(rhs), cmp));

    assert(etl::equal(begin(lhs), end(lhs), begin(rhs), end(rhs)));
    assert(!etl::equal(begin(lhs), end(lhs), begin(rhs), end(rhs), cmp));

    auto small = etl::array { T(1) };
    assert(!etl::equal(begin(lhs), end(lhs), begin(small), end(small), cmp));

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::uint8_t>());
    assert(test<etl::int8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::uint64_t>());
    assert(test<etl::int64_t>());
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
