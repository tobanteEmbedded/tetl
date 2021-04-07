/*
Copyright (c) Tobias Hienzsch. All rights reserved.

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

#ifndef TAETL_NET_BYTE_ORDER_HPP
#define TAETL_NET_BYTE_ORDER_HPP

#include "etl/cstdint.hpp"

namespace etl
{
namespace net
{
template <typename T>
constexpr auto ntoh(T) -> T = delete;
constexpr auto ntoh(uint8_t v) noexcept -> uint8_t { return v; }
constexpr auto ntoh(int8_t v) noexcept -> int8_t { return v; }
constexpr auto ntoh(uint16_t v) noexcept -> uint16_t
{
  return uint16_t(v << uint16_t(8)) | uint16_t(v >> uint16_t(8));
}
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
constexpr auto hton(int8_t v) noexcept -> int8_t { return v; }
constexpr auto hton(uint8_t v) noexcept -> uint8_t { return v; }
constexpr auto hton(uint16_t v) noexcept -> uint16_t { return ntoh(v); }
constexpr auto hton(uint32_t v) noexcept -> uint32_t { return ntoh(v); }

}  // namespace net
}  // namespace etl

#endif  // TAETL_NET_BYTE_ORDER_HPP
