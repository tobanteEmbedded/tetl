/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CMATH_NEXTAFTER_HPP
#define TETL_CMATH_NEXTAFTER_HPP

#include "etl/_bit/bit_cast.hpp"
#include "etl/_cstdint/uint_t.hpp"
#include "etl/_type_traits/conditional.hpp"
#include "etl/_type_traits/is_same.hpp"

namespace etl {

namespace detail {

template <typename T>
using nextafter_uint_t = etl::conditional_t<etl::is_same_v<float, T>,
    etl::uint32_t, etl::uint64_t>;

template <typename T>
[[nodiscard]] constexpr auto nextafter_impl(T from, T to) -> T
{
    using U             = nextafter_uint_t<T>;
    auto const fromBits = etl::bit_cast<U>(from);
    auto const toBits   = etl::bit_cast<U>(to);
    if (toBits == fromBits) { return to; }
    if (toBits > fromBits) { return etl::bit_cast<T>(fromBits + 1); }
    return etl::bit_cast<T>(fromBits - 1);
}
} // namespace detail

/// \brief Returns the next representable value of from in the direction of to.
/// If from equals to, to is returned.
///
/// https://en.cppreference.com/w/cpp/numeric/math/nextafter
[[nodiscard]] constexpr auto nextafter(float from, float to) noexcept -> float
{
    return detail::nextafter_impl(from, to);
}

/// \brief Returns the next representable value of from in the direction of to.
/// If from equals to, to is returned.
///
/// https://en.cppreference.com/w/cpp/numeric/math/nextafter
[[nodiscard]] constexpr auto nextafterf(float from, float to) noexcept -> float
{
    return detail::nextafter_impl(from, to);
}

/// \brief Returns the next representable value of from in the direction of to.
/// If from equals to, to is returned.
///
/// https://en.cppreference.com/w/cpp/numeric/math/nextafter
[[nodiscard]] constexpr auto nextafter(double from, double to) noexcept
    -> double
{
    return detail::nextafter_impl(from, to);
}

} // namespace etl

#endif // TETL_CMATH_NEXTAFTER_HPP