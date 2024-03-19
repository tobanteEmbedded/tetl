// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/functional.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    // equal_to
    {
        auto data = etl::array<T, 5>{T(1), T(1), T(1), T(2), T(3)};
        etl::unique(begin(data), end(data));
        CHECK(data[0] == T(1));
        CHECK(data[1] == T(2));
        CHECK(data[2] == T(3));
    }

    // not_equal_to
    {
        auto data = etl::array<T, 5>{T(1), T(1), T(1), T(2), T(3)};
        etl::unique(begin(data), end(data), etl::not_equal_to{});
        CHECK(data[0] == T(1));
        CHECK(data[1] == T(1));
        CHECK(data[2] == T(1));
    }

    // equal_to
    {
        auto src = etl::array<T, 5>{T(1), T(1), T(1), T(2), T(3)};
        decltype(src) dest{};

        etl::unique_copy(begin(src), end(src), begin(dest));
        CHECK(dest[0] == T(1));
        CHECK(dest[1] == T(2));
        CHECK(dest[2] == T(3));
    }

    // not_equal_to
    {
        auto src = etl::array<T, 5>{T(1), T(1), T(1), T(2), T(3)};
        decltype(src) dest{};

        auto cmp = etl::not_equal_to{};
        etl::unique_copy(begin(src), end(src), begin(dest), cmp);
        CHECK(dest[0] == T(1));
        CHECK(dest[1] == T(1));
        CHECK(dest[2] == T(1));
    }
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
