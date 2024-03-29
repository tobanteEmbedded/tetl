// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_POPCOUNT_HPP
#define TETL_BIT_POPCOUNT_HPP

#include <etl/_config/all.hpp>

#include <etl/_concepts/builtin_unsigned_integer.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>
#include <etl/_type_traits/is_same.hpp>

namespace etl {

namespace detail {

// https://en.wikichip.org/wiki/population_count
template <etl::builtin_unsigned_integer UInt>
[[nodiscard]] constexpr auto popcount_fallback(UInt val) noexcept -> int
{
    auto c = 0;
    for (; val != 0; val &= val - UInt(1)) {
        c++;
    }
    return c;
}

} // namespace detail

/// \brief Returns the number of 1 bits in the value of x.
///
/// \details This overload only participates in overload resolution if UInt is an
/// unsigned integer type (that is, unsigned char, unsigned short, unsigned int,
/// unsigned long, unsigned long long, or an extended unsigned integer type).
///
/// \ingroup bit
template <etl::builtin_unsigned_integer UInt>
[[nodiscard]] constexpr auto popcount(UInt val) noexcept -> int
{
    if (not etl::is_constant_evaluated()) {
#if __has_builtin(__builtin_popcount)
        if constexpr (sizeof(UInt) == sizeof(unsigned long long)) {
            return static_cast<int>(__builtin_popcountll(val));
        } else if constexpr (sizeof(UInt) == sizeof(unsigned long)) {
            return static_cast<int>(__builtin_popcountl(val));
        } else {
            return static_cast<int>(__builtin_popcount(val));
        }
#endif
    }

    return etl::detail::popcount_fallback(val);
}

} // namespace etl

#endif // TETL_BIT_POPCOUNT_HPP
