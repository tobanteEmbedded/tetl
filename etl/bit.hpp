/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_BIT_HPP
#define TAETL_BIT_HPP

#include "etl/cstring.hpp"
#include "etl/limits.hpp"
#include "etl/type_traits.hpp"

#include "etl/detail/sfinae.hpp"

namespace etl
{
/**
 * @brief Indicates the endianness of all scalar types.
 *
 * @details If all scalar types are little-endian, etl::endian::native equals
 * etl::endian::little. If all scalar types are big-endian,
 * etl::endian::native equals etl::endian::big
 *
 * @ref https://en.cppreference.com/w/cpp/types/endian
 */
enum class endian
{
#ifdef _WIN32
    little = 0,
    big    = 1,
    native = little
#else
    little = __ORDER_LITTLE_ENDIAN__,
    big    = __ORDER_BIG_ENDIAN__,
    native = __BYTE_ORDER__
#endif
};

/**
 * @brief Obtain a value of type To by reinterpreting the object representation of from.
 * Every bit in the value representation of the returned To object is equal to the
 * corresponding bit in the object representation of from.
 *
 * @details The values of padding bits in the returned To object are unspecified. If there
 * is no value of type To corresponding to the value representation produced, the behavior
 * is undefined. If there are multiple such values, which value is produced is
 * unspecified. This overload only participates in overload resolution if sizeof(To) ==
 * sizeof(From) and both To and From are TriviallyCopyable types.
 *
 * @ref https://en.cppreference.com/w/cpp/numeric/bit_cast
 */
template <
    typename To, typename From,
    TAETL_REQUIRES_((sizeof(To) == sizeof(From))
                    && is_trivially_copyable_v<From> && is_trivially_copyable_v<To>)>
constexpr auto bit_cast(const From& src) noexcept -> To
{
    static_assert(is_trivially_constructible_v<To>,
                  "This implementation additionally requires destination type to be "
                  "trivially constructible");

    To dst;
    etl::memcpy(&dst, &src, sizeof(To));
    return dst;
}

namespace detail
{
template <typename T>
using bit_unsigned_int = etl::bool_constant<
    etl::disjunction_v<etl::is_same<T, unsigned char>, etl::is_same<T, unsigned short>,
                       etl::is_same<T, unsigned int>, etl::is_same<T, unsigned long>,
                       etl::is_same<T, unsigned long long>>>;

template <typename T>
inline constexpr auto bit_unsigned_int_v = bit_unsigned_int<T>::value;

}  // namespace detail

template <typename T, TAETL_REQUIRES_(detail::bit_unsigned_int_v<T>)>
constexpr auto rotl(T t, int s) noexcept -> T
{
    auto const cnt    = static_cast<unsigned>(s);
    auto const digits = static_cast<unsigned>(etl::numeric_limits<T>::digits);
    if ((cnt % digits) == 0) { return t; }
    return (t << (cnt % digits)) | (t >> (digits - (cnt % digits)));
}

template <typename T, TAETL_REQUIRES_(detail::bit_unsigned_int_v<T>)>
constexpr auto rotr(T t, int s) noexcept -> T
{
    auto const cnt    = static_cast<unsigned>(s);
    auto const digits = static_cast<unsigned>(etl::numeric_limits<T>::digits);
    if ((cnt % digits) == 0) { return t; }
    return (t >> (cnt % digits)) | (t << (digits - (cnt % digits)));
}

/**
 * @brief Returns the number of 1 bits in the value of x.
 *
 * @details This overload only participates in overload resolution if T is an
 * unsigned integer type (that is, unsigned char, unsigned short, unsigned int,
 * unsigned long, unsigned long long, or an extended unsigned integer type).
 *
 */
template <typename T, TAETL_REQUIRES_(detail::bit_unsigned_int_v<T>)>
[[nodiscard]] constexpr auto popcount(T input) noexcept -> int
{
    auto count = T {0};
    while (input)
    {
        count = count + (input & T(1));
        input = input >> T(1);
    }
    return static_cast<int>(count);
}

/**
 * @brief Checks if x is an integral power of two.
 *
 * @details This overload only participates in overload resolution if T is an
 * unsigned integer type (that is, unsigned char, unsigned short, unsigned int,
 * unsigned long, unsigned long long, or an extended unsigned integer type).
 *
 * @return true if x is an integral power of two; otherwise false.
 */
template <typename T, TAETL_REQUIRES_(detail::bit_unsigned_int_v<T>)>
[[nodiscard]] constexpr auto has_single_bit(T x) noexcept -> bool
{
    return popcount(x) == 1;
}

/**
 * @brief Returns the number of consecutive 0 bits in the value of x, starting
 * from the most significant bit ("left").
 *
 * @details This overload only participates in overload resolution if T is an
 * unsigned integer type (that is, unsigned char, unsigned short, unsigned int,
 * unsigned long, unsigned long long, or an extended unsigned integer type).
 *
 * @return The number of consecutive 0 bits in the value of x, starting from the
 * most significant bit.
 */
template <typename T, TAETL_REQUIRES_(detail::bit_unsigned_int_v<T>)>
[[nodiscard]] constexpr auto countl_zero(T x) noexcept -> int
{
    auto const total_bits = etl::numeric_limits<T>::digits;
    if (x == T {0}) { return etl::numeric_limits<T>::digits; }

    int res = 0;
    while (!(x & (T {1} << (total_bits - 1))))
    {
        x = (x << T {1});
        res++;
    }

    return res;
}

/**
 * @brief Returns the number of consecutive 1 ("one") bits in the value of x,
 * starting from the most significant bit ("left").
 *
 * @details This overload only participates in overload resolution if T is an
 * unsigned integer type (that is, unsigned char, unsigned short, unsigned int,
 * unsigned long, unsigned long long, or an extended unsigned integer type).
 *
 * @return The number of consecutive 1 bits in the value of x, starting from the
 * most significant bit.
 */
template <typename T, TAETL_REQUIRES_(detail::bit_unsigned_int_v<T>)>
[[nodiscard]] constexpr auto countl_one(T x) noexcept -> int
{
    auto const total_bits = etl::numeric_limits<T>::digits;
    if (x == etl::numeric_limits<T>::max()) { return total_bits; }

    int res = 0;
    while (x & (T {1} << (total_bits - 1)))
    {
        x = (x << T {1});
        res++;
    }

    return res;
}

/**
 * @brief If x is not zero, calculates the number of bits needed to store the
 * value x, that is, 1+⌊log2(x)⌋. If x is zero, returns zero.
 *
 * @details This overload only participates in overload resolution if T is an
 * unsigned integer type (that is, unsigned char, unsigned short, unsigned int,
 * unsigned long, unsigned long long, or an extended unsigned integer type).
 */
template <typename T, TAETL_REQUIRES_(detail::bit_unsigned_int_v<T>)>
[[nodiscard]] constexpr auto bit_width(T x) noexcept -> int
{
    return etl::numeric_limits<T>::digits - etl::countl_zero(x);
}

}  // namespace etl

#endif  // TAETL_BIT_HPP