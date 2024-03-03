// SPDX-License-Identifier: BSL-1.0

#include <etl/array.hpp>

#include <etl/concepts.hpp>
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
        auto memory = etl::array<etl::byte, 64> {};
        auto empty  = Array {Alloc {memory}};
        assert(empty.size() == 0);
        assert(etl::as_const(empty).size() == 0);
        assert(empty.data() == nullptr);
        assert(etl::as_const(empty).data() == nullptr);
        assert(empty.begin() == nullptr);
        assert(etl::as_const(empty).begin() == nullptr);
        assert(empty.end() == nullptr);
        assert(etl::as_const(empty).end() == nullptr);
    }

    {
        auto memory = etl::array<etl::byte, 64> {};
        auto zeros  = Array {2, Alloc {memory}};
        assert(zeros.size() == 2);
        assert(etl::as_const(zeros).size() == 2);
        assert(zeros.data() != nullptr);
        assert(etl::as_const(zeros).data() != nullptr);
        assert(zeros.begin() != nullptr);
        assert(etl::as_const(zeros).begin() != nullptr);
        assert(zeros.end() != nullptr);
        assert(etl::as_const(zeros).end() != nullptr);
    }

    {
        auto memory = etl::array<etl::byte, 64> {};
        auto ones   = Array {4, T(1), Alloc {memory}};
        assert(ones.size() == 4);
        assert(etl::as_const(ones).size() == 4);
        assert(ones.data() != nullptr);
        assert(etl::as_const(ones).data() != nullptr);
        assert(ones.begin() != nullptr);
        assert(etl::as_const(ones).begin() != nullptr);
        assert(ones.end() != nullptr);
        assert(etl::as_const(ones).end() != nullptr);
    }

    return true;
}

static auto test_all() -> bool
{
    assert(test<etl::int8_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::int64_t>());
    assert(test<etl::uint8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::uint64_t>());
    assert(test<float>());
    assert(test<double>());
    return true;
}

auto main() -> int
{
    assert(test_all());
    return 0;
}
