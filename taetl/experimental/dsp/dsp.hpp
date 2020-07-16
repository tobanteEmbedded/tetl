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

#ifndef TAETL_DSP_DSP_HPP
#define TAETL_DSP_DSP_HPP

#include "taetl/definitions.hpp"
#include "taetl/utility.hpp"

namespace taetl
{
namespace dsp
{
struct identity
{
    constexpr identity() = default;

    template <typename T>
    constexpr auto operator()(T val) const
    {
        return val;
    }
};

template <typename T = float>
struct constant
{
    constexpr constant(T val) : val_ {val} { }

    template <typename... Args>
    constexpr auto operator()(Args...) const
    {
        return val_;
    }

private:
    T const val_;
};

namespace literals
{
constexpr auto operator""_K(long double val) -> constant<long double>
{
    return constant {val};
}
constexpr auto operator""_K(unsigned long long val)
    -> constant<unsigned long long>
{
    return constant {val};
}
}  // namespace literals

template <typename L, typename R>
struct pipe
{
    constexpr pipe(L lhs, R rhs) : lhs_ {lhs}, rhs_ {rhs} { }

    template <typename... T>
    constexpr auto operator()(T... val)
    {
        return call_rhs(lhs_(val...));
    }

private:
    template <typename... T>
    constexpr auto call_rhs(T... val)
    {
        return rhs_(taetl::forward<T>(val)...);
    }

    L lhs_;
    R rhs_;
};

template <typename L, typename R>
constexpr auto operator|(L lhs, R rhs)
{
    return pipe<L, R> {lhs, rhs};
}
}  // namespace dsp
}  // namespace taetl

#endif  // TAETL_DSP_DSP_HPP
