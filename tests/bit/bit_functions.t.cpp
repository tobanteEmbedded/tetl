/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/bit.hpp"

#include "etl/cstdint.hpp"

#include "testing/testing.hpp"

constexpr auto test_bit_ceil() -> bool
{
    assert(etl::bit_ceil(0b00000000U) == 0b00000001U);
    assert(etl::bit_ceil(0b00000001U) == 0b00000001U);
    assert(etl::bit_ceil(0b00000010U) == 0b00000010U);
    assert(etl::bit_ceil(0b00000011U) == 0b00000100U);
    assert(etl::bit_ceil(0b00000100U) == 0b00000100U);
    assert(etl::bit_ceil(0b00000101U) == 0b00001000U);
    assert(etl::bit_ceil(0b00000110U) == 0b00001000U);
    assert(etl::bit_ceil(0b00000111U) == 0b00001000U);
    assert(etl::bit_ceil(0b00001000U) == 0b00001000U);
    assert(etl::bit_ceil(0b00001001U) == 0b00010000U);
    return true;
}

constexpr auto test_bit_floor() -> bool
{
    assert(etl::bit_floor(0b00000000UL) == 0b00000000UL);
    assert(etl::bit_floor(0b00000001UL) == 0b00000001UL);
    assert(etl::bit_floor(0b00000010UL) == 0b00000010UL);
    assert(etl::bit_floor(0b00000011UL) == 0b00000010UL);
    assert(etl::bit_floor(0b00000100UL) == 0b00000100UL);
    assert(etl::bit_floor(0b00000101UL) == 0b00000100UL);
    assert(etl::bit_floor(0b00000110UL) == 0b00000100UL);
    assert(etl::bit_floor(0b00000111UL) == 0b00000100UL);
    assert(etl::bit_floor(0b00001000UL) == 0b00001000UL);
    assert(etl::bit_floor(0b00001001UL) == 0b00001000UL);
    return true;
}

template <typename T>
constexpr auto test_bit_width() -> bool
{
    assert(etl::bit_width(T { 0 }) == 0);
    assert(etl::bit_width(T { 1 }) == 1);
    assert(etl::bit_width(T { 2 }) == 2);
    assert(etl::bit_width(T { 3 }) == 2);
    assert(etl::bit_width(T { 4 }) == 3);
    assert(etl::bit_width(T { 5 }) == 3);
    assert(etl::bit_width(T { 6 }) == 3);
    assert(etl::bit_width(T { 7 }) == 3);
    return true;
}

template <typename T>
constexpr auto test_popcount() -> bool
{
    assert(etl::popcount(T { 1 }) == 1);
    assert(etl::popcount(T { 2 }) == 1);
    assert(etl::popcount(T { 3 }) == 2);
    return true;
}

constexpr auto test_rotl() -> bool
{
    etl::uint8_t const i = 0b00011101;

    assert(etl::rotl(i, 0) == 0b00011101);
    assert(etl::rotl(i, 1) == 0b00111010);
    assert(etl::rotl(i, 4) == 0b11010001);
    assert(etl::rotl(i, 9) == 0b00111010);
    assert(etl::rotl(i, -1) == 0b10001110);

    return true;
}

constexpr auto test_rotr() -> bool
{
    etl::uint8_t const i = 0b00011101;

    assert(etl::rotr(i, 0) == 0b00011101);
    assert(etl::rotr(i, 1) == 0b10001110);
    assert(etl::rotr(i, 9) == 0b10001110);
    assert(etl::rotr(i, -1) == 0b00111010);

    return true;
}

template <typename T>
constexpr auto test_countl_zero() -> bool
{
    assert(etl::countl_zero(T { 0 }) == etl::numeric_limits<T>::digits);

    assert(etl::countl_zero(etl::uint8_t { 0b1111'1111 }) == 0);
    assert(etl::countl_zero(etl::uint8_t { 0b0111'1111 }) == 1);
    assert(etl::countl_zero(etl::uint8_t { 0b0011'1111 }) == 2);
    assert(etl::countl_zero(etl::uint8_t { 0b0001'1111 }) == 3);
    assert(etl::countl_zero(etl::uint8_t { 0b0000'1111 }) == 4);
    assert(etl::countl_zero(etl::uint8_t { 0b0000'0000 }) == 8);

    assert(etl::countl_zero(etl::uint16_t { 0b1000'0000'1111'1111 }) == 0);
    assert(etl::countl_zero(etl::uint16_t { 0b0100'0000'1111'1111 }) == 1);
    assert(etl::countl_zero(etl::uint16_t { 0b0010'0000'1111'1111 }) == 2);
    assert(etl::countl_zero(etl::uint16_t { 0b0001'0000'1111'1111 }) == 3);
    assert(etl::countl_zero(etl::uint16_t { 0b0000'0000'0000'0001 }) == 15);

    return true;
}

template <typename T>
constexpr auto test_countl_one() -> bool
{
    assert(etl::countl_one(T { etl::numeric_limits<T>::max() })
           == etl::numeric_limits<T>::digits);

    assert(etl::countl_one(etl::uint8_t { 0b0000'0000 }) == 0);
    assert(etl::countl_one(etl::uint8_t { 0b1111'1111 }) == 8);
    assert(etl::countl_one(etl::uint8_t { 0b1110'1111 }) == 3);

    assert(etl::countl_one(etl::uint16_t { 0b1000'0000'1111'1111 }) == 1);
    assert(etl::countl_one(etl::uint16_t { 0b1111'0000'1111'1111 }) == 4);
    return true;
}

template <typename T>
constexpr auto test_countr_zero() -> bool
{
    assert(etl::countr_zero(T { 0 }) == etl::numeric_limits<T>::digits);

    assert(etl::countr_zero(T { 0b0000'0001 }) == 0);
    assert(etl::countr_zero(T { 0b0000'0010 }) == 1);
    assert(etl::countr_zero(T { 0b0000'0100 }) == 2);
    assert(etl::countr_zero(T { 0b0000'1000 }) == 3);
    assert(etl::countr_zero(T { 0b0001'0000 }) == 4);
    assert(etl::countr_zero(T { 0b0010'0000 }) == 5);
    assert(etl::countr_zero(T { 0b0100'0000 }) == 6);
    assert(etl::countr_zero(T { 0b1000'0000 }) == 7);
    return true;
}

template <typename T>
constexpr auto test_countr_one() -> bool
{
    assert(etl::countr_one(etl::numeric_limits<T>::max())
           == etl::numeric_limits<T>::digits);

    assert(etl::countr_one(T { 0b1111'1111 }) == 8);
    assert(etl::countr_one(T { 0b0111'1111 }) == 7);
    assert(etl::countr_one(T { 0b0011'1111 }) == 6);
    assert(etl::countr_one(T { 0b0001'1111 }) == 5);
    assert(etl::countr_one(T { 0b0000'1111 }) == 4);
    assert(etl::countr_one(T { 0b0000'0000 }) == 0);

    return true;
}

template <typename T>
constexpr auto test_has_single_bit() -> bool
{
    assert(etl::has_single_bit(T { 1 << 0 }));
    assert(etl::has_single_bit(T { 1 << 1 }));
    assert(etl::has_single_bit(T { 1 << 2 }));
    assert(etl::has_single_bit(T { 1 << 3 }));
    assert(etl::has_single_bit(T { 1 << 4 }));

    assert(!etl::has_single_bit(T { 0 }));
    assert(!etl::has_single_bit(T { 3 }));
    assert(!etl::has_single_bit(T { 3 << 4 }));

    return true;
}

constexpr auto test_all() -> bool
{
    assert(etl::endian::big != etl::endian::little);

    assert(test_bit_ceil());
    assert(test_bit_floor());

    assert(test_bit_width<etl::uint8_t>());
    assert(test_bit_width<etl::uint16_t>());
    assert(test_bit_width<etl::uint32_t>());
    assert(test_bit_width<etl::uint64_t>());

    assert(test_rotl());
    assert(test_rotr());

    assert(test_popcount<etl::uint8_t>());
    assert(test_popcount<etl::uint16_t>());
    assert(test_popcount<etl::uint32_t>());
    assert(test_popcount<etl::uint64_t>());

    assert(test_countl_zero<etl::uint8_t>());
    assert(test_countl_zero<etl::uint16_t>());
    assert(test_countl_zero<etl::uint32_t>());
    assert(test_countl_zero<etl::uint64_t>());

    assert(test_countl_one<etl::uint8_t>());
    assert(test_countl_one<etl::uint16_t>());
    assert(test_countl_one<etl::uint32_t>());
    assert(test_countl_one<etl::uint64_t>());

    assert(test_countr_zero<etl::uint8_t>());
    assert(test_countr_zero<etl::uint16_t>());
    assert(test_countr_zero<etl::uint32_t>());
    assert(test_countr_zero<etl::uint64_t>());

    assert(test_countr_one<etl::uint8_t>());
    assert(test_countr_one<etl::uint16_t>());
    assert(test_countr_one<etl::uint32_t>());
    assert(test_countr_one<etl::uint64_t>());

    assert(test_has_single_bit<etl::uint8_t>());
    assert(test_has_single_bit<etl::uint16_t>());
    assert(test_has_single_bit<etl::uint32_t>());
    assert(test_has_single_bit<etl::uint64_t>());

    return true;
}
auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}