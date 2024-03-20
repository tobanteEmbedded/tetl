// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/functional.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    auto lhs = etl::array<T, 2>{T{0}, T{1}};
    auto rhs = etl::array<T, 2>{T{0}, T{1}};
    auto cmp = etl::not_equal_to{};

    CHECK(etl::equal(begin(lhs), end(lhs), begin(rhs)));
    CHECK_FALSE(etl::equal(begin(lhs), end(lhs), begin(rhs), cmp));

    CHECK(etl::equal(begin(lhs), end(lhs), begin(rhs), end(rhs)));
    CHECK_FALSE(etl::equal(begin(lhs), end(lhs), begin(rhs), end(rhs), cmp));

    auto small = etl::array{T(1)};
    CHECK_FALSE(etl::equal(begin(lhs), end(lhs), begin(small), end(small), cmp));

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
