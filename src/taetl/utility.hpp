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

#ifndef TAETL_UTILITY_HPP
#define TAETL_UTILITY_HPP

#include "taetl/type_traits.hpp"

namespace taetl
{
/**
 * @brief taetl::move is used to indicate that an object t may be "moved from",
 * i.e. allowing the efficient transfer of resources from t to another object.
 * In particular, std::move produces an xvalue expression that identifies its
 * argument t. It is exactly equivalent to a static_cast to an rvalue reference
 * type.
 * @tparam T
 * @param t
 * @return static_cast<typename taetl::remove_reference<T>::type&&>(t)
 */
template <class T>
constexpr auto move(T&& t) noexcept ->
    typename taetl::remove_reference<T>::type&&
{
    return static_cast<typename taetl::remove_reference<T>::type&&>(t);
}

template <class T>
constexpr auto forward(taetl::remove_reference_t<T>& param) noexcept -> T&&
{
    return static_cast<T&&>(param);
}

template <class T>
constexpr auto forward(taetl::remove_reference_t<T>&& param) noexcept -> T&&
{
    return static_cast<T&&>(param);
}

template <class T1, class T2>
struct pair
{
    using first_type  = T1;
    using second_type = T2;

    constexpr pair() : first {}, second {} { }
    constexpr pair(T1 const& t1, T2 const& t2) : first {t1}, second {t2} { }

    template <class U1, class U2>
    constexpr pair(const pair<U1, U2>& p) : first {p.first}, second {p.second}
    {
    }

    pair(pair const& p) = default;

    pair& operator=(pair const& p)
    {
        first  = p.first;
        second = p.second;
        return *this;
    }

    template <class U1, class U2>
    pair& operator=(pair<U1, U2>& p)
    {
        first  = p.first;
        second = p.second;
        return *this;
    }

    pair(pair&& p) = default;

    pair& operator=(pair&& __p)
    {
        first  = taetl::move(__p.first);
        second = taetl::move(__p.second);
        return *this;
    }

    template <class _U1, class _U2>
    pair& operator=(pair<_U1, _U2>&& __p)
    {
        first  = taetl::move(__p.first);
        second = taetl::move(__p.second);
        return *this;
    }

    T1 first;
    T2 second;
};
}  // namespace taetl

#endif  // TAETL_UTILITY_HPP
