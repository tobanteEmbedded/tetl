// SPDX-License-Identifier: BSL-1.0

#include <etl/bit.hpp>

#include <etl/cstddef.hpp>
#include <etl/cstdint.hpp>
#include <etl/limits.hpp>

#include "testing/testing.hpp"

namespace {

template <typename UInt>
concept has_test_bit = requires(UInt val, UInt bit) { etl::test_bit(val, bit); };

template <typename UInt>
constexpr auto test() -> bool
{
    ASSERT_NOEXCEPT(etl::test_bit(UInt(1), UInt(0)));
    ASSERT_SAME_TYPE(decltype(etl::test_bit(UInt(1), UInt(0))), bool);

    ASSERT(not etl::test_bit(UInt(0b00000000), UInt(0)));
    ASSERT(not etl::test_bit(UInt(0b00000000), UInt(1)));
    ASSERT(not etl::test_bit(UInt(0b00000000), UInt(2)));

    ASSERT(etl::test_bit(UInt(0b00000001), UInt(0)));
    ASSERT(etl::test_bit(UInt(0b00000010), UInt(1)));
    ASSERT(etl::test_bit(UInt(0b00000100), UInt(2)));

    ASSERT(etl::test_bit(UInt(0b00000111), UInt(0)));
    ASSERT(etl::test_bit(UInt(0b00000111), UInt(1)));
    ASSERT(etl::test_bit(UInt(0b00000111), UInt(2)));

    return true;
}

constexpr auto test_all() -> bool
{
    ASSERT(has_test_bit<etl::uint8_t>);
    ASSERT(has_test_bit<etl::uint16_t>);
    ASSERT(has_test_bit<etl::uint32_t>);
    ASSERT(has_test_bit<etl::uint64_t>);

    ASSERT(has_test_bit<unsigned char>);
    ASSERT(has_test_bit<unsigned short>);
    ASSERT(has_test_bit<unsigned int>);
    ASSERT(has_test_bit<unsigned long>);
    ASSERT(has_test_bit<unsigned long long>);

    ASSERT(not has_test_bit<etl::int8_t>);
    ASSERT(not has_test_bit<etl::int16_t>);
    ASSERT(not has_test_bit<etl::int32_t>);
    ASSERT(not has_test_bit<etl::int64_t>);
    ASSERT(not has_test_bit<etl::ptrdiff_t>);

    ASSERT(not has_test_bit<signed char>);
    ASSERT(not has_test_bit<signed short>);
    ASSERT(not has_test_bit<signed int>);
    ASSERT(not has_test_bit<signed long>);
    ASSERT(not has_test_bit<signed long long>);

    ASSERT(not has_test_bit<bool>);
    ASSERT(not has_test_bit<char>);
    ASSERT(not has_test_bit<char8_t>);
    ASSERT(not has_test_bit<char16_t>);
    ASSERT(not has_test_bit<char32_t>);

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
