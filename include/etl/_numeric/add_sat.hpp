// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_NUMERIC_ADD_SAT_HPP
#define TETL_NUMERIC_ADD_SAT_HPP

#include <etl/_algorithm/clamp.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_cstdint/int_t.hpp>
#include <etl/_cstdint/uint_t.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_type_traits/always_false.hpp>
#include <etl/_type_traits/is_signed.hpp>
#include <etl/_type_traits/is_unsigned.hpp>

namespace etl {

template <etl::integral T>
[[nodiscard]] constexpr auto add_sat(T x, T y) noexcept -> T
{
    constexpr auto min = etl::numeric_limits<T>::min();
    constexpr auto max = etl::numeric_limits<T>::max();

    if constexpr (sizeof(T) < sizeof(int) and etl::same_as<decltype(x + y), int>) {
        return static_cast<T>(etl::clamp(x + y, int(min), int(max)));
    } else if constexpr (sizeof(T) < sizeof(unsigned) and etl::same_as<decltype(x + y), unsigned>) {
        return static_cast<T>(etl::clamp(x + y, unsigned(min), unsigned(max)));
    } else if constexpr (sizeof(T) == 2 and etl::is_signed_v<T>) {
        return static_cast<T>(etl::clamp(etl::int32_t(x) + etl::int32_t(y), etl::int32_t(min), etl::int32_t(max)));
    } else if constexpr (sizeof(T) == 2 and etl::is_unsigned_v<T>) {
        return static_cast<T>(etl::clamp(etl::uint32_t(x) + etl::uint32_t(y), etl::uint32_t(min), etl::uint32_t(max)));
    } else if constexpr (sizeof(T) == 4 and etl::is_signed_v<T>) {
        return static_cast<T>(etl::clamp(etl::int64_t(x) + etl::int64_t(y), etl::int64_t(min), etl::int64_t(max)));
    } else if constexpr (sizeof(T) == 4 and etl::is_unsigned_v<T>) {
        return static_cast<T>(etl::clamp(etl::uint64_t(x) + etl::uint64_t(y), etl::uint64_t(min), etl::uint64_t(max)));
    } else {
        static_assert(etl::always_false<T>);
    }
}

} // namespace etl

#endif // TETL_NUMERIC_ADD_SAT_HPP
