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

#ifndef ETL_EXPERIMENTAL_META_ALGORITHM_ALL_OF_HPP
#define ETL_EXPERIMENTAL_META_ALGORITHM_ALL_OF_HPP

#include "etl/cstddef.hpp"
#include "etl/tuple.hpp"
#include "etl/type_traits.hpp"

namespace etl::experimental::meta {

namespace detail {

template <etl::size_t... Idx, typename... Ts, typename F>
constexpr auto all_of_impl(etl::index_sequence<Idx...>, tuple<Ts...>& t, F f)
    -> etl::bool_constant<(etl::is_same_v<decltype(f(etl::get<Idx>(t))),
                               etl::bool_constant<true>> && ...)>
{
    return {};
}

} // namespace detail

template <typename... Ts, typename F>
constexpr auto all_of(tuple<Ts...>& t, F f)
{
    constexpr auto indices = etl::make_index_sequence<sizeof...(Ts)> {};
    return detail::all_of_impl(indices, t, f);
}

} // namespace etl::experimental::meta

#endif // ETL_EXPERIMENTAL_META_ALGORITHM_ALL_OF_HPP
