// SPDX-License-Identifier: BSL-1.0

#include "etl/algorithm.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/iterator.hpp"
#include "etl/numeric.hpp"
#include "etl/vector.hpp"

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    {
        auto a        = etl::array {T(1), T(2)};
        decltype(a) b = {};

        etl::swap_ranges(begin(a), end(a), begin(b));
        assert(a[0] == T(0));
        assert(a[1] == T(0));
        assert(b[0] == T(1));
        assert(b[1] == T(2));
    }

    {
        auto data = etl::array {T(1), T(2)};
        etl::iter_swap(begin(data), begin(data) + 1);
        assert(data[0] == T(2));
        assert(data[1] == T(1));
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
