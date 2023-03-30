// SPDX-License-Identifier: BSL-1.0

#include "etl/algorithm.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/numeric.hpp"

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    // built-in
    {
        auto data = etl::array<T, 4> {};
        etl::iota(begin(data), end(data), T { 0 });
        etl::reverse(begin(data), end(data));

        assert(data[0] == 3);
        assert(data[1] == 2);
        assert(data[2] == 1);
        assert(data[3] == 0);
    }

    // struct
    {
        struct S {
            T data;
        };

        auto arr = etl::array {
            S { T(1) },
            S { T(2) },
        };

        etl::reverse(begin(arr), end(arr));

        assert(arr[0].data == T(2));
        assert(arr[1].data == T(1));
    }
    // built-in
    {
        auto source = etl::array<T, 4> {};
        etl::iota(begin(source), end(source), T { 0 });

        auto destination = etl::array<T, 4> {};
        etl::reverse_copy(begin(source), end(source), begin(destination));

        assert(destination[0] == 3);
        assert(destination[1] == 2);
        assert(destination[2] == 1);
        assert(destination[3] == 0);
    }

    // struct
    {
        struct S {
            T data;
        };

        auto source = etl::array {
            S { T(1) },
            S { T(2) },
        };

        decltype(source) destination {};
        etl::reverse_copy(begin(source), end(source), begin(destination));

        assert(destination[0].data == T(2));
        assert(destination[1].data == T(1));
    }

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
