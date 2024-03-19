// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/numeric.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    // built-in
    {
        auto data = etl::array<T, 4>{};
        etl::iota(begin(data), end(data), T{0});
        etl::reverse(begin(data), end(data));

        CHECK(data[0] == 3);
        CHECK(data[1] == 2);
        CHECK(data[2] == 1);
        CHECK(data[3] == 0);
    }

    // struct
    {
        struct S {
            T data;
        };

        auto arr = etl::array{
            S{T(1)},
            S{T(2)},
        };

        etl::reverse(begin(arr), end(arr));

        CHECK(arr[0].data == T(2));
        CHECK(arr[1].data == T(1));
    }
    // built-in
    {
        auto source = etl::array<T, 4>{};
        etl::iota(begin(source), end(source), T{0});

        auto destination = etl::array<T, 4>{};
        etl::reverse_copy(begin(source), end(source), begin(destination));

        CHECK(destination[0] == 3);
        CHECK(destination[1] == 2);
        CHECK(destination[2] == 1);
        CHECK(destination[3] == 0);
    }

    // struct
    {
        struct S {
            T data;
        };

        auto source = etl::array{
            S{T(1)},
            S{T(2)},
        };

        decltype(source) destination{};
        etl::reverse_copy(begin(source), end(source), begin(destination));

        CHECK(destination[0].data == T(2));
        CHECK(destination[1].data == T(1));
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
