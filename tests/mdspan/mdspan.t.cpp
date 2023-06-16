// SPDX-License-Identifier: BSL-1.0

#include <etl/mdspan.hpp>

#include <etl/cstdint.hpp>

#include "testing/testing.hpp"

template <typename ElementType>
[[nodiscard]] constexpr auto test_mdspan() -> bool
{
    auto tc = etl::mdspan<ElementType, etl::extents<etl::size_t, etl::dynamic_extent>> {};
    (void)tc;
    return true;
}

[[nodiscard]] constexpr auto test_all() -> bool
{
    assert(test_mdspan<etl::uint8_t>());
    assert(test_mdspan<etl::uint16_t>());
    assert(test_mdspan<etl::uint32_t>());
    assert(test_mdspan<etl::uint64_t>());

    assert(test_mdspan<etl::int8_t>());
    assert(test_mdspan<etl::int16_t>());
    assert(test_mdspan<etl::int32_t>());
    assert(test_mdspan<etl::int64_t>());

    assert(test_mdspan<float>());
    assert(test_mdspan<double>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
