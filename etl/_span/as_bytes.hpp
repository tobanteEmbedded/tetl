// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_SPAN_AS_BYTES_HPP
#define TETL_SPAN_AS_BYTES_HPP

#include "etl/_cstddef/byte.hpp"
#include "etl/_span/dynamic_extent.hpp"
#include "etl/_span/span.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_const.hpp"

namespace etl {

namespace detail {
template <typename T, etl::size_t N>
inline constexpr etl::size_t span_as_bytes_size
    = N == etl::dynamic_extent ? etl::dynamic_extent : sizeof(T) * N;
}

/// \brief Obtains a view to the object representation of the elements of the
/// span s.
///
/// \details If N is dynamic_extent, the extent of the returned span S is also
/// dynamic_extent; otherwise it is sizeof(T) * N.
template <typename T, size_t N>
[[nodiscard]] auto as_bytes(span<T, N> s) noexcept
    -> span<byte const, detail::span_as_bytes_size<T, N>>
{
    return { reinterpret_cast<byte const*>(s.data()), s.size_bytes() };
}

/// \brief Obtains a view to the object representation of the elements of the
/// span s.
///
/// \details If N is dynamic_extent, the extent of the returned span S is also
/// dynamic_extent; otherwise it is sizeof(T) * N. Only participates in overload
/// resolution if is_const_v<T> is false.
template <typename T, size_t N>
[[nodiscard]] auto as_writable_bytes(span<T, N> s) noexcept
    -> enable_if_t<!is_const_v<T>, span<byte, detail::span_as_bytes_size<T, N>>>
{
    return { reinterpret_cast<byte*>(s.data()), s.size_bytes() };
}

} // namespace etl

#endif // TETL_SPAN_AS_BYTES_HPP