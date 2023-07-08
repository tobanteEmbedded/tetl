// SPDX-License-Identifier: BSL-1.0

#include <etl/mdspan.hpp>

#include <etl/cstdint.hpp>

#include "testing/testing.hpp"

template <typename ElementType>
[[nodiscard]] constexpr auto test_one() -> bool
{
    using extents_t = etl::extents<etl::size_t, etl::dynamic_extent>;
    using mdspan_t  = etl::mdspan<ElementType, extents_t>;

    assert(etl::is_same_v<typename mdspan_t::element_type, ElementType>);
    assert(etl::is_same_v<typename mdspan_t::value_type, ElementType>);
    assert(etl::is_same_v<typename mdspan_t::size_type, etl::size_t>);
    assert(etl::is_same_v<typename mdspan_t::index_type, etl::size_t>);

    auto tc = etl::mdspan<ElementType, etl::extents<etl::size_t, etl::dynamic_extent>> {};
    (void)tc;
    return true;
}

[[nodiscard]] constexpr auto test_mdspan() -> bool
{
    assert(test_one<etl::uint8_t>());
    assert(test_one<etl::uint16_t>());
    assert(test_one<etl::uint32_t>());
    assert(test_one<etl::uint64_t>());

    assert(test_one<etl::int8_t>());
    assert(test_one<etl::int16_t>());
    assert(test_one<etl::int32_t>());
    assert(test_one<etl::int64_t>());

    assert(test_one<float>());
    assert(test_one<double>());

    return true;
}

auto main() -> int
{
    assert(test_mdspan());
    static_assert(test_mdspan());
    return 0;
}
