// SPDX-License-Identifier: BSL-1.0

#include <etl/iterator.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    auto data = etl::array{T(1), T(2), T(3)};
    CHECK(*data.rbegin() == *etl::make_reverse_iterator(data.end()));
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
