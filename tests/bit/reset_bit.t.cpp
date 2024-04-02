// SPDX-License-Identifier: BSL-1.0

#include <etl/bit.hpp>

#include <etl/cstddef.hpp>
#include <etl/cstdint.hpp>
#include <etl/limits.hpp>

#include "testing/testing.hpp"

namespace {

template <typename T>
concept has_reset_bit = requires(T val, T bit) { etl::reset_bit(val, bit); };

template <typename T>
constexpr auto test() -> bool
{
    CHECK_NOEXCEPT(etl::reset_bit(T(1), T(0)));
    CHECK_SAME_TYPE(decltype(etl::reset_bit(T(1), T(0))), T);

    CHECK(etl::reset_bit(T(0b00000001), T(0)) == T(0b00000000));
    CHECK(etl::reset_bit(T(0b00000010), T(1)) == T(0b00000000));
    CHECK(etl::reset_bit(T(0b00000100), T(2)) == T(0b00000000));
    CHECK(etl::reset_bit(T(0b00000011), T(1)) == T(0b00000001));

    CHECK_NOEXCEPT(etl::reset_bit<0>(T(1)));
    CHECK_SAME_TYPE(decltype(etl::reset_bit<0>(T(1))), T);

    CHECK(etl::reset_bit<0>(T(0b00000001)) == T(0b00000000));
    CHECK(etl::reset_bit<1>(T(0b00000010)) == T(0b00000000));
    CHECK(etl::reset_bit<2>(T(0b00000100)) == T(0b00000000));
    CHECK(etl::reset_bit<1>(T(0b00000011)) == T(0b00000001));

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(has_reset_bit<etl::uint8_t>);
    CHECK(has_reset_bit<etl::uint16_t>);
    CHECK(has_reset_bit<etl::uint32_t>);
    CHECK(has_reset_bit<etl::uint64_t>);

    CHECK(has_reset_bit<unsigned char>);
    CHECK(has_reset_bit<unsigned short>);
    CHECK(has_reset_bit<unsigned int>);
    CHECK(has_reset_bit<unsigned long>);
    CHECK(has_reset_bit<unsigned long long>);

    CHECK_FALSE(has_reset_bit<etl::int8_t>);
    CHECK_FALSE(has_reset_bit<etl::int16_t>);
    CHECK_FALSE(has_reset_bit<etl::int32_t>);
    CHECK_FALSE(has_reset_bit<etl::int64_t>);
    CHECK_FALSE(has_reset_bit<etl::ptrdiff_t>);

    CHECK_FALSE(has_reset_bit<signed char>);
    CHECK_FALSE(has_reset_bit<signed short>);
    CHECK_FALSE(has_reset_bit<signed int>);
    CHECK_FALSE(has_reset_bit<signed long>);
    CHECK_FALSE(has_reset_bit<signed long long>);

    CHECK_FALSE(has_reset_bit<bool>);
    CHECK_FALSE(has_reset_bit<char>);
    CHECK_FALSE(has_reset_bit<char8_t>);
    CHECK_FALSE(has_reset_bit<char16_t>);
    CHECK_FALSE(has_reset_bit<char32_t>);

    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::size_t>());

#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)
    CHECK(test<etl::uint64_t>());
#endif

    return true;
}

} // namespace

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
