/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

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

/**
 * @example tuple.cpp
 */

#ifndef TAETL_TUPLE_HPP
#define TAETL_TUPLE_HPP

#include "definitions.hpp"

namespace etl
{
/**
 * @brief
 *
 * @todo Implement index_sequence & tuple_size
 */
template <typename First, typename... Rest>
struct tuple : public tuple<Rest...>
{
    tuple(First f, Rest... rest) : tuple<Rest...>(rest...), first(f) { }

    First first;
};

template <typename First>
struct tuple<First>
{
    tuple(First f) : first(f) { }

    First first;
};

namespace detail
{
template <int index, typename First, typename... Rest>
struct get_impl
{
    static auto value(const tuple<First, Rest...>* t)
        -> decltype(get_impl<index - 1, Rest...>::value(t))
    {
        return get_impl<index - 1, Rest...>::value(t);
    }
};

template <typename First, typename... Rest>
struct get_impl<0, First, Rest...>
{
    static auto value(const tuple<First, Rest...>* t) -> First
    {
        return t->first;
    }
};

}  // namespace detail

template <int index, typename First, typename... Rest>
auto get(const tuple<First, Rest...>& t)
    -> decltype(detail::get_impl<index, First, Rest...>::value(&t))
{
    return detail::get_impl<index, First, Rest...>::value(&t);
}
}  // namespace etl

#endif  // TAETL_TUPLE_HPP
