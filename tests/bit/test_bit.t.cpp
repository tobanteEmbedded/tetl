// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/bit.hpp>
    #include <etl/cstddef.hpp>
    #include <etl/cstdint.hpp>
#endif

namespace {

template <typename UInt>
concept has_test_bit = requires(UInt val, UInt bit) { etl::test_bit(val, bit); };

template <typename UInt>
constexpr auto test() -> bool
{
    CHECK_NOEXCEPT(etl::test_bit(UInt(1), UInt(0)));
    CHECK_SAME_TYPE(decltype(etl::test_bit(UInt(1), UInt(0))), bool);

    CHECK_FALSE(etl::test_bit(UInt(0b00000000), UInt(0)));
    CHECK_FALSE(etl::test_bit(UInt(0b00000000), UInt(1)));
    CHECK_FALSE(etl::test_bit(UInt(0b00000000), UInt(2)));

    CHECK(etl::test_bit(UInt(0b00000001), UInt(0)));
    CHECK(etl::test_bit(UInt(0b00000010), UInt(1)));
    CHECK(etl::test_bit(UInt(0b00000100), UInt(2)));

    CHECK(etl::test_bit(UInt(0b00000111), UInt(0)));
    CHECK(etl::test_bit(UInt(0b00000111), UInt(1)));
    CHECK(etl::test_bit(UInt(0b00000111), UInt(2)));

    CHECK_NOEXCEPT(etl::test_bit<0>(UInt(1)));
    CHECK_SAME_TYPE(decltype(etl::test_bit<0>(UInt(1))), bool);

    CHECK_FALSE(etl::test_bit<0>(UInt(0b00000000)));
    CHECK_FALSE(etl::test_bit<1>(UInt(0b00000000)));
    CHECK_FALSE(etl::test_bit<2>(UInt(0b00000000)));

    CHECK(etl::test_bit<0>(UInt(0b00000001)));
    CHECK(etl::test_bit<1>(UInt(0b00000010)));
    CHECK(etl::test_bit<2>(UInt(0b00000100)));

    CHECK(etl::test_bit<0>(UInt(0b00000111)));
    CHECK(etl::test_bit<1>(UInt(0b00000111)));
    CHECK(etl::test_bit<2>(UInt(0b00000111)));

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(has_test_bit<etl::uint8_t>);
    CHECK(has_test_bit<etl::uint16_t>);
    CHECK(has_test_bit<etl::uint32_t>);
    CHECK(has_test_bit<etl::uint64_t>);

    CHECK(has_test_bit<unsigned char>);
    CHECK(has_test_bit<unsigned short>);
    CHECK(has_test_bit<unsigned int>);
    CHECK(has_test_bit<unsigned long>);

    CHECK_FALSE(has_test_bit<etl::int8_t>);
    CHECK_FALSE(has_test_bit<etl::int16_t>);
    CHECK_FALSE(has_test_bit<etl::int32_t>);
    CHECK_FALSE(has_test_bit<etl::int64_t>);
    CHECK_FALSE(has_test_bit<etl::ptrdiff_t>);

    CHECK_FALSE(has_test_bit<signed char>);
    CHECK_FALSE(has_test_bit<signed short>);
    CHECK_FALSE(has_test_bit<signed int>);
    CHECK_FALSE(has_test_bit<signed long>);

    CHECK_FALSE(has_test_bit<bool>);
    CHECK_FALSE(has_test_bit<char>);
    CHECK_FALSE(has_test_bit<char8_t>);
    CHECK_FALSE(has_test_bit<char16_t>);
    CHECK_FALSE(has_test_bit<char32_t>);

    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::uint64_t>());
    CHECK(test<etl::size_t>());

    return true;
}

} // namespace

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
