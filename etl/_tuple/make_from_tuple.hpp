
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

#ifndef TETL_TUPLE_MAKE_FROM_TUPLE_HPP
#define TETL_TUPLE_MAKE_FROM_TUPLE_HPP

#include "etl/_tuple/tuple.hpp"
#include "etl/_tuple/tuple_size.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/index_sequence.hpp"
#include "etl/_type_traits/is_constructible.hpp"
#include "etl/_type_traits/remove_reference.hpp"
#include "etl/_utility/forward.hpp"

namespace etl {

namespace detail {

template <typename T, typename Tuple, size_t... I>
constexpr auto make_from_tuple_impl(Tuple&& t, index_sequence<I...>) -> T
{
    static_assert(is_constructible_v<T, decltype(get<I>(declval<Tuple>()))...>);
    return T(get<I>(forward<Tuple>(t))...);
}

} // namespace detail

template <typename T, typename Tuple>
[[nodiscard]] constexpr auto make_from_tuple(Tuple&& t) -> T
{
    return detail::make_from_tuple_impl<T>(forward<Tuple>(t),
        make_index_sequence<tuple_size_v<remove_reference_t<Tuple>>> {});
}

} // namespace etl

#endif // TETL_TUPLE_MAKE_FROM_TUPLE_HPP
