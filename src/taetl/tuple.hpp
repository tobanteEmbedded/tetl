/*
Copyright (c) 2019, Tobias Hienzsch
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

#ifndef TAETL_TUPLE_HPP
#define TAETL_TUPLE_HPP

#include "definitions.hpp"

namespace taetl
{
/**
 * @brief Namespace for the taetl library.
 */
template <typename First, typename... Rest>
struct tuple : public tuple<Rest...>
{
    tuple(First f, Rest... rest) : tuple<Rest...>(rest...), first(f) {}

    First first;
};

template <typename First>
struct tuple<First>
{
    tuple(First f) : first(f) {}

    First first;
};

template <int index, typename First, typename... Rest>
struct GetImpl
{
    static auto value(const tuple<First, Rest...>* t)
        -> decltype(GetImpl<index - 1, Rest...>::value(t))
    {
        return GetImpl<index - 1, Rest...>::value(t);
    }
};

template <typename First, typename... Rest>
struct GetImpl<0, First, Rest...>
{
    static First value(const tuple<First, Rest...>* t) { return t->first; }
};

template <int index, typename First, typename... Rest>
auto get(const tuple<First, Rest...>& t)
    -> decltype(GetImpl<index, First, Rest...>::value(&t))
{  // typename Type<index, First, Rest...>::value {
    return GetImpl<index, First, Rest...>::value(&t);
}
}  // namespace taetl

#endif  // TAETL_TUPLE_HPP
