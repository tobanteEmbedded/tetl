// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/bit.hpp>
    #include <etl/cstdint.hpp>
    #include <etl/limits.hpp>
#endif

static constexpr auto test_bit_ceil() -> bool
{
    CHECK(etl::bit_ceil(0b00000000U) == 0b00000001U);
    CHECK(etl::bit_ceil(0b00000001U) == 0b00000001U);
    CHECK(etl::bit_ceil(0b00000010U) == 0b00000010U);
    CHECK(etl::bit_ceil(0b00000011U) == 0b00000100U);
    CHECK(etl::bit_ceil(0b00000100U) == 0b00000100U);
    CHECK(etl::bit_ceil(0b00000101U) == 0b00001000U);
    CHECK(etl::bit_ceil(0b00000110U) == 0b00001000U);
    CHECK(etl::bit_ceil(0b00000111U) == 0b00001000U);
    CHECK(etl::bit_ceil(0b00001000U) == 0b00001000U);
    CHECK(etl::bit_ceil(0b00001001U) == 0b00010000U);
    return true;
}

static constexpr auto test_bit_floor() -> bool
{
    CHECK(etl::bit_floor(0b00000000UL) == 0b00000000UL);
    CHECK(etl::bit_floor(0b00000001UL) == 0b00000001UL);
    CHECK(etl::bit_floor(0b00000010UL) == 0b00000010UL);
    CHECK(etl::bit_floor(0b00000011UL) == 0b00000010UL);
    CHECK(etl::bit_floor(0b00000100UL) == 0b00000100UL);
    CHECK(etl::bit_floor(0b00000101UL) == 0b00000100UL);
    CHECK(etl::bit_floor(0b00000110UL) == 0b00000100UL);
    CHECK(etl::bit_floor(0b00000111UL) == 0b00000100UL);
    CHECK(etl::bit_floor(0b00001000UL) == 0b00001000UL);
    CHECK(etl::bit_floor(0b00001001UL) == 0b00001000UL);
    return true;
}

template <typename T>
static constexpr auto test_bit_width() -> bool
{
    CHECK(etl::bit_width(T{0}) == 0);
    CHECK(etl::bit_width(T{1}) == 1);
    CHECK(etl::bit_width(T{2}) == 2);
    CHECK(etl::bit_width(T{3}) == 2);
    CHECK(etl::bit_width(T{4}) == 3);
    CHECK(etl::bit_width(T{5}) == 3);
    CHECK(etl::bit_width(T{6}) == 3);
    CHECK(etl::bit_width(T{7}) == 3);
    return true;
}

static constexpr auto test_rotl() -> bool
{
    etl::uint8_t const i = 0b00011101;

    CHECK(etl::rotl(i, 0) == 0b00011101);
    CHECK(etl::rotl(i, 1) == 0b00111010);
    CHECK(etl::rotl(i, 4) == 0b11010001);
    CHECK(etl::rotl(i, 9) == 0b00111010);
    CHECK(etl::rotl(i, -1) == 0b10001110);

    return true;
}

static constexpr auto test_rotr() -> bool
{
    etl::uint8_t const i = 0b00011101;

    CHECK(etl::rotr(i, 0) == 0b00011101);
    CHECK(etl::rotr(i, 1) == 0b10001110);
    CHECK(etl::rotr(i, 9) == 0b10001110);
    CHECK(etl::rotr(i, -1) == 0b00111010);

    return true;
}

template <typename T>
static constexpr auto test_countl_zero() -> bool
{
    CHECK(etl::countl_zero(T{0}) == etl::numeric_limits<T>::digits);

    CHECK(etl::countl_zero(etl::uint8_t{0b1111'1111}) == 0);
    CHECK(etl::countl_zero(etl::uint8_t{0b0111'1111}) == 1);
    CHECK(etl::countl_zero(etl::uint8_t{0b0011'1111}) == 2);
    CHECK(etl::countl_zero(etl::uint8_t{0b0001'1111}) == 3);
    CHECK(etl::countl_zero(etl::uint8_t{0b0000'1111}) == 4);
    CHECK(etl::countl_zero(etl::uint8_t{0b0000'0000}) == 8);

    CHECK(etl::countl_zero(etl::uint16_t{0b1000'0000'1111'1111}) == 0);
    CHECK(etl::countl_zero(etl::uint16_t{0b0100'0000'1111'1111}) == 1);
    CHECK(etl::countl_zero(etl::uint16_t{0b0010'0000'1111'1111}) == 2);
    CHECK(etl::countl_zero(etl::uint16_t{0b0001'0000'1111'1111}) == 3);
    CHECK(etl::countl_zero(etl::uint16_t{0b0000'0000'0000'0001}) == 15);

    return true;
}

template <typename T>
static constexpr auto test_countl_one() -> bool
{
    CHECK(etl::countl_one(T{etl::numeric_limits<T>::max()}) == etl::numeric_limits<T>::digits);

    CHECK(etl::countl_one(etl::uint8_t{0b0000'0000}) == 0);
    CHECK(etl::countl_one(etl::uint8_t{0b1111'1111}) == 8);
    CHECK(etl::countl_one(etl::uint8_t{0b1110'1111}) == 3);

    CHECK(etl::countl_one(etl::uint16_t{0b1000'0000'1111'1111}) == 1);
    CHECK(etl::countl_one(etl::uint16_t{0b1111'0000'1111'1111}) == 4);
    return true;
}

template <typename T>
static constexpr auto test_countr_zero() -> bool
{
    CHECK(etl::countr_zero(T{0}) == etl::numeric_limits<T>::digits);

    CHECK(etl::countr_zero(T{0b0000'0001}) == 0);
    CHECK(etl::countr_zero(T{0b0000'0010}) == 1);
    CHECK(etl::countr_zero(T{0b0000'0100}) == 2);
    CHECK(etl::countr_zero(T{0b0000'1000}) == 3);
    CHECK(etl::countr_zero(T{0b0001'0000}) == 4);
    CHECK(etl::countr_zero(T{0b0010'0000}) == 5);
    CHECK(etl::countr_zero(T{0b0100'0000}) == 6);
    CHECK(etl::countr_zero(T{0b1000'0000}) == 7);
    return true;
}

template <typename T>
static constexpr auto test_countr_one() -> bool
{
    CHECK(etl::countr_one(etl::numeric_limits<T>::max()) == etl::numeric_limits<T>::digits);

    CHECK(etl::countr_one(T{0b1111'1111}) == 8);
    CHECK(etl::countr_one(T{0b0111'1111}) == 7);
    CHECK(etl::countr_one(T{0b0011'1111}) == 6);
    CHECK(etl::countr_one(T{0b0001'1111}) == 5);
    CHECK(etl::countr_one(T{0b0000'1111}) == 4);
    CHECK(etl::countr_one(T{0b0000'0000}) == 0);

    return true;
}

template <typename T>
static constexpr auto test_has_single_bit() -> bool
{
    CHECK(etl::has_single_bit(T{1 << 0}));
    CHECK(etl::has_single_bit(T{1 << 1}));
    CHECK(etl::has_single_bit(T{1 << 2}));
    CHECK(etl::has_single_bit(T{1 << 3}));
    CHECK(etl::has_single_bit(T{1 << 4}));

    CHECK_FALSE(etl::has_single_bit(T{0}));
    CHECK_FALSE(etl::has_single_bit(T{3}));
    CHECK_FALSE(etl::has_single_bit(T{3 << 4}));

    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(etl::endian::big != etl::endian::little);

    CHECK(test_bit_ceil());
    CHECK(test_bit_floor());

    CHECK(test_bit_width<etl::uint8_t>());
    CHECK(test_bit_width<etl::uint16_t>());
    CHECK(test_bit_width<etl::uint32_t>());
    CHECK(test_bit_width<etl::uint64_t>());

    CHECK(test_rotl());
    CHECK(test_rotr());

    CHECK(test_countl_zero<etl::uint8_t>());
    CHECK(test_countl_zero<etl::uint16_t>());
    CHECK(test_countl_zero<etl::uint32_t>());
    CHECK(test_countl_zero<etl::uint64_t>());

    CHECK(test_countl_one<etl::uint8_t>());
    CHECK(test_countl_one<etl::uint16_t>());
    CHECK(test_countl_one<etl::uint32_t>());
    CHECK(test_countl_one<etl::uint64_t>());

    CHECK(test_countr_zero<etl::uint8_t>());
    CHECK(test_countr_zero<etl::uint16_t>());
    CHECK(test_countr_zero<etl::uint32_t>());
    CHECK(test_countr_zero<etl::uint64_t>());

    CHECK(test_countr_one<etl::uint8_t>());
    CHECK(test_countr_one<etl::uint16_t>());
    CHECK(test_countr_one<etl::uint32_t>());
    CHECK(test_countr_one<etl::uint64_t>());

    CHECK(test_has_single_bit<etl::uint8_t>());
    CHECK(test_has_single_bit<etl::uint16_t>());
    CHECK(test_has_single_bit<etl::uint32_t>());
    CHECK(test_has_single_bit<etl::uint64_t>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
