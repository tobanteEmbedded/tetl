// SPDX-License-Identifier: BSL-1.0

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
concept has_set_bit = requires(UInt val, UInt bit) { etl::set_bit(val, bit); };

template <typename UInt>
constexpr auto test() -> bool
{
    CHECK_NOEXCEPT(etl::set_bit(UInt(1), UInt(0)));
    CHECK_SAME_TYPE(decltype(etl::set_bit(UInt(1), UInt(0))), UInt);

    CHECK(etl::set_bit(UInt(0b00000000), UInt(0)) == UInt(0b00000001));
    CHECK(etl::set_bit(UInt(0b00000000), UInt(1)) == UInt(0b00000010));
    CHECK(etl::set_bit(UInt(0b00000000), UInt(2)) == UInt(0b00000100));

    CHECK_NOEXCEPT(etl::set_bit<0>(UInt(1)));
    CHECK_SAME_TYPE(decltype(etl::set_bit<0>(UInt(1))), UInt);

    CHECK(etl::set_bit<0>(UInt(0b00000000)) == UInt(0b00000001));
    CHECK(etl::set_bit<1>(UInt(0b00000000)) == UInt(0b00000010));
    CHECK(etl::set_bit<2>(UInt(0b00000000)) == UInt(0b00000100));

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(has_set_bit<etl::uint8_t>);
    CHECK(has_set_bit<etl::uint16_t>);
    CHECK(has_set_bit<etl::uint32_t>);
    CHECK(has_set_bit<etl::uint64_t>);

    CHECK(has_set_bit<unsigned char>);
    CHECK(has_set_bit<unsigned short>);
    CHECK(has_set_bit<unsigned int>);
    CHECK(has_set_bit<unsigned long>);
    CHECK(has_set_bit<unsigned long long>);

    CHECK_FALSE(has_set_bit<etl::int8_t>);
    CHECK_FALSE(has_set_bit<etl::int16_t>);
    CHECK_FALSE(has_set_bit<etl::int32_t>);
    CHECK_FALSE(has_set_bit<etl::int64_t>);
    CHECK_FALSE(has_set_bit<etl::ptrdiff_t>);

    CHECK_FALSE(has_set_bit<signed char>);
    CHECK_FALSE(has_set_bit<signed short>);
    CHECK_FALSE(has_set_bit<signed int>);
    CHECK_FALSE(has_set_bit<signed long>);
    CHECK_FALSE(has_set_bit<signed long long>);

    CHECK_FALSE(has_set_bit<bool>);
    CHECK_FALSE(has_set_bit<char>);
    CHECK_FALSE(has_set_bit<char8_t>);
    CHECK_FALSE(has_set_bit<char16_t>);
    CHECK_FALSE(has_set_bit<char32_t>);

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
