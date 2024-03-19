// SPDX-License-Identifier: BSL-1.0

#include <etl/bit.hpp>

#include <etl/cstddef.hpp>
#include <etl/cstdint.hpp>
#include <etl/limits.hpp>

#include "testing/testing.hpp"

namespace {

template <typename T>
concept has_flip_bit = requires(T val, T bit) { etl::flip_bit(val, bit); };

template <typename T>
constexpr auto test() -> bool
{
    ASSERT_NOEXCEPT(etl::flip_bit(T(1), T(0)));
    ASSERT_SAME_TYPE(decltype(etl::flip_bit(T(1), T(0))), T);

    ASSERT(etl::flip_bit(T(0b00000001), T(0)) == T(0b00000000));
    ASSERT(etl::flip_bit(T(0b00000010), T(1)) == T(0b00000000));
    ASSERT(etl::flip_bit(T(0b00000100), T(2)) == T(0b00000000));
    ASSERT(etl::flip_bit(T(0b00000011), T(3)) == T(0b00001011));

    return true;
}

constexpr auto test_all() -> bool
{
    ASSERT(has_flip_bit<etl::uint8_t>);
    ASSERT(has_flip_bit<etl::uint16_t>);
    ASSERT(has_flip_bit<etl::uint32_t>);
    ASSERT(has_flip_bit<etl::uint64_t>);

    ASSERT(has_flip_bit<unsigned char>);
    ASSERT(has_flip_bit<unsigned short>);
    ASSERT(has_flip_bit<unsigned int>);
    ASSERT(has_flip_bit<unsigned long>);
    ASSERT(has_flip_bit<unsigned long long>);

    ASSERT(not has_flip_bit<etl::int8_t>);
    ASSERT(not has_flip_bit<etl::int16_t>);
    ASSERT(not has_flip_bit<etl::int32_t>);
    ASSERT(not has_flip_bit<etl::int64_t>);
    ASSERT(not has_flip_bit<etl::ptrdiff_t>);

    ASSERT(not has_flip_bit<signed char>);
    ASSERT(not has_flip_bit<signed short>);
    ASSERT(not has_flip_bit<signed int>);
    ASSERT(not has_flip_bit<signed long>);
    ASSERT(not has_flip_bit<signed long long>);

    ASSERT(not has_flip_bit<bool>);
    ASSERT(not has_flip_bit<char>);
    ASSERT(not has_flip_bit<char8_t>);
    ASSERT(not has_flip_bit<char16_t>);
    ASSERT(not has_flip_bit<char32_t>);

    ASSERT(test<etl::uint8_t>());
    ASSERT(test<etl::uint16_t>());
    ASSERT(test<etl::uint32_t>());
    ASSERT(test<etl::uint64_t>());
    ASSERT(test<etl::size_t>());

    return true;
}

} // namespace

auto main() -> int
{
    ASSERT(test_all());
    static_assert(test_all());
    return 0;
}
