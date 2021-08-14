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

#ifndef ETL_EXPERIMENTAL_META_DETAIL_INTEGRAL_CONSTANT_HPP
#define ETL_EXPERIMENTAL_META_DETAIL_INTEGRAL_CONSTANT_HPP

#include "etl/type_traits.hpp"

namespace etl::experimental::meta {

using etl::integral_constant;

template <typename Rhs, Rhs R, typename Lhs, Lhs L>
[[nodiscard]] constexpr auto operator+(
    integral_constant<Rhs, R> /*l*/, integral_constant<Lhs, L> /*r*/) noexcept
{
    return integral_constant<decltype(L + R), L + R> {};
}

template <typename Rhs, Rhs R, typename Lhs, Lhs L>
[[nodiscard]] constexpr auto operator==(
    integral_constant<Rhs, R> /*l*/, integral_constant<Lhs, L> /*r*/) noexcept
{
    return integral_constant<bool, L == R> {};
}

template <typename Rhs, Rhs R, typename Lhs, Lhs L>
[[nodiscard]] constexpr auto operator!=(
    integral_constant<Rhs, R> /*l*/, integral_constant<Lhs, L> /*r*/) noexcept
{
    return integral_constant<bool, L != R> {};
}

template <int Val>
inline constexpr auto int_c = integral_constant<int, Val> {};

} // namespace etl::experimental::meta

#endif // ETL_EXPERIMENTAL_META_DETAIL_INTEGRAL_CONSTANT_HPP