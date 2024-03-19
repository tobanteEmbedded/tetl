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
        assert(data[0] == T(1));
        assert(data[1] == T(2));
        assert(data[2] == T(3));
    }

    // not_equal_to
    {
        auto data = etl::array<T, 5>{T(1), T(1), T(1), T(2), T(3)};
        etl::unique(begin(data), end(data), etl::not_equal_to{});
        assert(data[0] == T(1));
        assert(data[1] == T(1));
        assert(data[2] == T(1));
    }

    // equal_to
    {
        auto src = etl::array<T, 5>{T(1), T(1), T(1), T(2), T(3)};
        decltype(src) dest{};

        etl::unique_copy(begin(src), end(src), begin(dest));
        assert(dest[0] == T(1));
        assert(dest[1] == T(2));
        assert(dest[2] == T(3));
    }

    // not_equal_to
    {
        auto src = etl::array<T, 5>{T(1), T(1), T(1), T(2), T(3)};
        decltype(src) dest{};

        auto cmp = etl::not_equal_to{};
        etl::unique_copy(begin(src), end(src), begin(dest), cmp);
        assert(dest[0] == T(1));
        assert(dest[1] == T(1));
        assert(dest[2] == T(1));
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
    STATIC_CHECK(test_all());
    return 0;
}
