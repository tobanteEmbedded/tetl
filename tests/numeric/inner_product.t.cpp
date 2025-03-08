// SPDX-License-Identifier: BSL-1.0

#include <etl/numeric.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>

#include "testing/testing.hpp"

template <typename T>
static constexpr auto test() -> bool
{
    // 0 1 2 3 4
    etl::array a{T(0), T(1), T(2), T(3), T(4)};

    // 5 4 3 2 1
    etl::array b{T(5), T(4), T(2), T(3), T(1)};

    auto product = etl::inner_product(a.begin(), a.end(), b.begin(), T{0});
    CHECK(product == T{21});

    auto p = etl::inner_product(a.begin(), a.end(), b.begin(), T{0}, etl::plus<T>{}, etl::equal_to<T>{});
    CHECK(p == T{2});
    return true;
}

static constexpr auto test_all() -> bool
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
