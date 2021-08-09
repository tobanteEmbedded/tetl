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

#ifndef TETL_DETAIL_TYPE_TRAITS_ALIGNED_UNION_HPP
#define TETL_DETAIL_TYPE_TRAITS_ALIGNED_UNION_HPP

#include "etl/_cstddef/size_t.hpp"

namespace etl {

namespace detail {
template <typename T>
[[nodiscard]] constexpr auto vmax(T val) -> T
{
    return val;
}

template <typename T0, typename T1, typename... Ts>
[[nodiscard]] constexpr auto vmax(T0 val1, T1 val2, Ts... vs) -> T0
{
    return (val1 > val2) ? vmax(val1, vs...) : vmax(val2, vs...);
}
} // namespace detail

/// \brief Provides the nested type type, which is a trivial standard-layout
/// type of a size and alignment suitable for use as uninitialized storage for
/// an object of any of the types listed in Types. The size of the storage is at
/// least Len. aligned_union also determines the strictest (largest) alignment
/// requirement among all Types and makes it available as the constant
/// alignment_value. If sizeof...(Types) == 0 or if any of the types in Types is
/// not a complete object type, the behavior is undefined. It is
/// implementation-defined whether any extended alignment is supported. The
/// behavior of a program that adds specializations for aligned_union is
/// undefined.
template <size_t Len, typename... Types>
struct aligned_union {
    static constexpr size_t alignment_value = detail::vmax(alignof(Types)...);

    struct type {
        alignas(
            alignment_value) char storage[detail::vmax(Len, sizeof(Types)...)];
    };
};

template <size_t Len, typename... Types>
using aligned_union_t = typename aligned_union<Len, Types...>::type;

} // namespace etl

#endif // TETL_DETAIL_TYPE_TRAITS_ALIGNED_UNION_HPP