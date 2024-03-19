// SPDX-License-Identifier: BSL-1.0

#include <etl/bit.hpp>

#include <etl/cstddef.hpp>
#include <etl/cstdint.hpp>
#include <etl/limits.hpp>

#include "testing/testing.hpp"

namespace {

template <typename UInt>
concept has_set_bit = requires(UInt val, UInt bit) { etl::set_bit(val, bit); };

template <typename UInt>
constexpr auto test() -> bool
{
    ASSERT_NOEXCEPT(etl::set_bit(UInt(1), UInt(0)));
    ASSERT_SAME_TYPE(decltype(etl::set_bit(UInt(1), UInt(0))), UInt);

    ASSERT(etl::set_bit(UInt(0b00000000), UInt(0)) == UInt(0b00000001));
    ASSERT(etl::set_bit(UInt(0b00000000), UInt(1)) == UInt(0b00000010));
    ASSERT(etl::set_bit(UInt(0b00000000), UInt(2)) == UInt(0b00000100));

    ASSERT_NOEXCEPT(etl::set_bit<0>(UInt(1)));
    ASSERT_SAME_TYPE(decltype(etl::set_bit<0>(UInt(1))), UInt);

    ASSERT(etl::set_bit<0>(UInt(0b00000000)) == UInt(0b00000001));
    ASSERT(etl::set_bit<1>(UInt(0b00000000)) == UInt(0b00000010));
    ASSERT(etl::set_bit<2>(UInt(0b00000000)) == UInt(0b00000100));

    return true;
}

constexpr auto test_all() -> bool
{
    ASSERT(has_set_bit<etl::uint8_t>);
    ASSERT(has_set_bit<etl::uint16_t>);
    ASSERT(has_set_bit<etl::uint32_t>);
    ASSERT(has_set_bit<etl::uint64_t>);

    ASSERT(has_set_bit<unsigned char>);
    ASSERT(has_set_bit<unsigned short>);
    ASSERT(has_set_bit<unsigned int>);
    ASSERT(has_set_bit<unsigned long>);
    ASSERT(has_set_bit<unsigned long long>);

    ASSERT(not has_set_bit<etl::int8_t>);
    ASSERT(not has_set_bit<etl::int16_t>);
    ASSERT(not has_set_bit<etl::int32_t>);
    ASSERT(not has_set_bit<etl::int64_t>);
    ASSERT(not has_set_bit<etl::ptrdiff_t>);

    ASSERT(not has_set_bit<signed char>);
    ASSERT(not has_set_bit<signed short>);
    ASSERT(not has_set_bit<signed int>);
    ASSERT(not has_set_bit<signed long>);
    ASSERT(not has_set_bit<signed long long>);

    ASSERT(not has_set_bit<bool>);
    ASSERT(not has_set_bit<char>);
    ASSERT(not has_set_bit<char8_t>);
    ASSERT(not has_set_bit<char16_t>);
    ASSERT(not has_set_bit<char32_t>);

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
