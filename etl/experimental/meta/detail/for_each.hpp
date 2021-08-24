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

#ifndef ETL_EXPERIMENTAL_META_DETAIL_FOR_EACH_HPP
#define ETL_EXPERIMENTAL_META_DETAIL_FOR_EACH_HPP

#include "etl/cstddef.hpp"
#include "etl/tuple.hpp"
#include "etl/type_traits.hpp"

namespace etl::experimental::meta {

namespace detail {

template <bool WithI, etl::size_t... Index, typename... Ts, typename Func>
auto for_each_impl(etl::index_sequence<Index...>, etl::tuple<Ts...>& t, Func f)
{
    if constexpr (WithI) {
        (f(Index, etl::get<Index>(t)), ...);
    } else {
        (f(etl::get<Index>(t)), ...);
    }
}
} // namespace detail

template <typename... Ts, typename Func>
constexpr auto for_each(etl::tuple<Ts...>& t, Func f) -> void
{
    constexpr auto indices = etl::make_index_sequence<sizeof...(Ts)> {};
    detail::for_each_impl<false>(indices, t, f);
}

template <typename... Ts, typename Func>
constexpr auto for_each_indexed(etl::tuple<Ts...>& t, Func f) -> void
{
    constexpr auto indices = etl::make_index_sequence<sizeof...(Ts)> {};
    detail::for_each_impl<true>(indices, t, f);
}

} // namespace etl::experimental::meta

#endif // ETL_EXPERIMENTAL_META_DETAIL_FOR_EACH_HPP
