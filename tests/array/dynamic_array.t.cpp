// SPDX-License-Identifier: BSL-1.0

#include <etl/array.hpp>

#include <etl/concepts.hpp>
#include <etl/cstdint.hpp>
#include <etl/memory.hpp>
#include <etl/utility.hpp>

#include "testing/testing.hpp"

template <typename T>
auto test() -> bool
{
    using Alloc = etl::monotonic_allocator<T>;
    using Array = etl::dynamic_array<T, Alloc>;

    static_assert(etl::same_as<typename Array::value_type, T>);
    static_assert(etl::same_as<typename Array::allocator_type, Alloc>);
    static_assert(etl::same_as<typename Array::size_type, etl::size_t>);
    static_assert(etl::same_as<typename Array::difference_type, etl::ptrdiff_t>);
    static_assert(etl::same_as<typename Array::pointer, T*>);
    static_assert(etl::same_as<typename Array::const_pointer, T const*>);

    {
        auto memory = etl::array<etl::byte, 64>{};
        auto empty  = Array{Alloc{memory}};
        CHECK(empty.size() == 0);
        CHECK(etl::as_const(empty).size() == 0);
        CHECK(empty.data() == nullptr);
        CHECK(etl::as_const(empty).data() == nullptr);
        CHECK(empty.begin() == nullptr);
        CHECK(etl::as_const(empty).begin() == nullptr);
        CHECK(empty.end() == nullptr);
        CHECK(etl::as_const(empty).end() == nullptr);
    }

    {
        auto memory = etl::array<etl::byte, 64>{};
        auto zeros  = Array{2, Alloc{memory}};
        CHECK(zeros.size() == 2);
        CHECK(etl::as_const(zeros).size() == 2);
        CHECK(zeros.data() != nullptr);
        CHECK(etl::as_const(zeros).data() != nullptr);
        CHECK(zeros.begin() != nullptr);
        CHECK(etl::as_const(zeros).begin() != nullptr);
        CHECK(zeros.end() != nullptr);
        CHECK(etl::as_const(zeros).end() != nullptr);
    }

    {
        auto memory = etl::array<etl::byte, 64>{};
        auto ones   = Array{4, T(1), Alloc{memory}};
        CHECK(ones.size() == 4);
        CHECK(etl::as_const(ones).size() == 4);
        CHECK(ones.data() != nullptr);
        CHECK(etl::as_const(ones).data() != nullptr);
        CHECK(ones.begin() != nullptr);
        CHECK(etl::as_const(ones).begin() != nullptr);
        CHECK(ones.end() != nullptr);
        CHECK(etl::as_const(ones).end() != nullptr);
    }

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
