// SPDX-License-Identifier: BSL-1.0

#include <etl/array.hpp>
#include <etl/concepts.hpp>
#include <etl/mdspan.hpp>
#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

template <typename ElementType>
constexpr auto test_one(etl::array<ElementType, 2> elements) -> bool
{
    using accessor_t = etl::default_accessor<ElementType>;

    static_assert(etl::is_empty_v<accessor_t>);

    static_assert(etl::is_nothrow_default_constructible_v<accessor_t>);
    static_assert(etl::is_nothrow_move_constructible_v<accessor_t>);
    static_assert(etl::is_nothrow_move_assignable_v<accessor_t>);
    static_assert(etl::is_nothrow_swappable_v<accessor_t>);
    static_assert(etl::is_trivially_copyable_v<accessor_t>);

    static_assert(etl::same_as<typename accessor_t::offset_policy, accessor_t>);
    static_assert(etl::same_as<typename accessor_t::element_type, ElementType>);
    static_assert(etl::same_as<typename accessor_t::reference, ElementType&>);
    static_assert(etl::same_as<typename accessor_t::data_handle_type, ElementType*>);

    auto accessor = accessor_t {};
    assert(accessor.access(elements.data(), 0) == elements[0]);
    assert(accessor.access(elements.data(), 1) == elements[1]);
    assert(accessor.offset(elements.data(), 0) == etl::next(elements.data(), 0));
    assert(accessor.offset(elements.data(), 1) == etl::next(elements.data(), 1));

    return true;
}

constexpr auto test_default_accessor() -> bool
{
    assert(test_one<char>({ 'a', 'b' }));

    assert(test_one<etl::uint8_t>({ 0, 1 }));
    assert(test_one<etl::uint16_t>({ 0, 1 }));
    assert(test_one<etl::uint32_t>({ 0, 1 }));
    assert(test_one<etl::uint64_t>({ 0, 1 }));

    assert(test_one<etl::int8_t>({ 0, 1 }));
    assert(test_one<etl::int16_t>({ 0, 1 }));
    assert(test_one<etl::int32_t>({ 0, 1 }));
    assert(test_one<etl::int64_t>({ 0, 1 }));

    assert(test_one<etl::size_t>({ 0, 1 }));
    assert(test_one<etl::ptrdiff_t>({ 0, 1 }));

    assert(test_one<float>({ 0.0F, 1.0F }));
    assert(test_one<double>({ 0.0, 1.0 }));

    return true;
}

auto main() -> int
{
    assert(test_default_accessor());
    static_assert(test_default_accessor());
    return 0;
}