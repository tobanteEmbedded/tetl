// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_NET_BYTE_ORDER_HPP
#define TETL_NET_BYTE_ORDER_HPP

#include <etl/version.hpp>

#include <etl/cstdint.hpp>

namespace etl::experimental::net {
template <typename T>
constexpr auto ntoh(T) -> T = delete;
constexpr auto ntoh(char v) noexcept -> char { return v; }
constexpr auto ntoh(uint8_t v) noexcept -> uint8_t { return v; }
constexpr auto ntoh(int8_t v) noexcept -> int8_t { return v; }
constexpr auto ntoh(uint16_t v) noexcept -> uint16_t { return uint16_t(v << uint16_t(8)) | uint16_t(v >> uint16_t(8)); }
constexpr auto ntoh(uint32_t v) noexcept -> uint32_t
{
    auto const a = v << 24;
    auto const b = (v & 0x0000FF00) << 8;
    auto const c = (v & 0x00FF0000) >> 8;
    auto const d = v >> 24;

    return a | b | c | d;
}

template <typename T>
constexpr auto hton(T) -> T = delete;
constexpr auto hton(char v) noexcept -> char { return v; }
constexpr auto hton(int8_t v) noexcept -> int8_t { return v; }
constexpr auto hton(uint8_t v) noexcept -> uint8_t { return v; }
constexpr auto hton(uint16_t v) noexcept -> uint16_t { return ntoh(v); }
constexpr auto hton(uint32_t v) noexcept -> uint32_t { return ntoh(v); }

} // namespace etl::experimental::net

#endif // TETL_NET_BYTE_ORDER_HPP
