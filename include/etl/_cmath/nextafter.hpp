// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CMATH_NEXTAFTER_HPP
#define TETL_CMATH_NEXTAFTER_HPP

#include <etl/_bit/bit_cast.hpp>
#include <etl/_cstdint/uint_t.hpp>
#include <etl/_type_traits/conditional.hpp>
#include <etl/_type_traits/is_same.hpp>

namespace etl {

namespace detail {

template <typename T>
[[nodiscard]] constexpr auto nextafter_impl(T from, T to) -> T
{
    using U             = etl::conditional_t<sizeof(T) == 4U, etl::uint32_t, etl::uint64_t>;
    auto const fromBits = etl::bit_cast<U>(from);
    auto const toBits   = etl::bit_cast<U>(to);
    if (toBits == fromBits) {
        return to;
    }
    if (toBits > fromBits) {
        return etl::bit_cast<T>(fromBits + 1);
    }
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
[[nodiscard]] constexpr auto nextafter(double from, double to) noexcept -> double
{
    return detail::nextafter_impl(from, to);
}

} // namespace etl

#endif // TETL_CMATH_NEXTAFTER_HPP
