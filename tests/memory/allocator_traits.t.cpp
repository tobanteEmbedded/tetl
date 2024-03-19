// SPDX-License-Identifier: BSL-1.0

#include <etl/memory.hpp>

#include <etl/array.hpp>
#include <etl/concepts.hpp>
#include <etl/cstddef.hpp>
#include <etl/cstdint.hpp>
#include <etl/span.hpp>

#include "testing/testing.hpp"

template <typename T>
auto test() -> bool
{
    using Alloc  = etl::monotonic_allocator<T>;
    using Traits = etl::allocator_traits<Alloc>;
    static_assert(etl::same_as<typename Traits::allocator_type, Alloc>);
    static_assert(etl::same_as<typename Traits::value_type, T>);
    static_assert(etl::same_as<typename Traits::pointer, T*>);
    static_assert(etl::same_as<typename Traits::const_pointer, T const*>);
    static_assert(etl::same_as<typename Traits::void_pointer, void*>);
    static_assert(etl::same_as<typename Traits::const_void_pointer, void const*>);
    static_assert(etl::same_as<typename Traits::size_type, typename Alloc::size_type>);
    static_assert(etl::same_as<typename Traits::difference_type, typename Alloc::difference_type>);

    auto buffer = etl::array<etl::byte, 64>{};
    auto alloc  = Alloc{buffer};
    auto* ptr   = alloc.allocate(1);
    CHECK(ptr != nullptr);
    alloc.deallocate(ptr, 1);

    return true;
}

static auto test_all() -> bool
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
    CHECK(test_all());
    return 0;
}
