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

#ifndef TETL_ARRAY_TO_ARRAY_HPP
#define TETL_ARRAY_TO_ARRAY_HPP

#include "etl/_array/array.hpp"
#include "etl/_type_traits/index_sequence.hpp"
#include "etl/_type_traits/remove_cv.hpp"
#include "etl/_utility/move.hpp"

namespace etl {

namespace detail {
template <typename T, size_t N, size_t... I>
[[nodiscard]] constexpr auto to_array_impl(
    T (&a)[N], index_sequence<I...> /*unused*/) -> array<remove_cv_t<T>, N>
{
    return { { a[I]... } };
}

template <typename T, size_t N, size_t... I>
[[nodiscard]] constexpr auto to_array_impl(
    T(&&a)[N], index_sequence<I...> /*unused*/) -> array<remove_cv_t<T>, N>
{
    return { { move(a[I])... } };
}

} // namespace detail

/// \brief Creates a array from the one dimensional built-in array a. The
/// elements of the array are copy-initialized from the corresponding element of
/// a. Copying or moving multidimensional built-in array is not supported.
/// \group to_array
template <typename T, size_t N>
[[nodiscard]] constexpr auto to_array(T (&a)[N]) -> array<remove_cv_t<T>, N>
{
    return detail::to_array_impl(a, make_index_sequence<N> {});
}

/// \group to_array
template <typename T, size_t N>
[[nodiscard]] constexpr auto to_array(T(&&a)[N])
{
    return detail::to_array_impl(move(a), make_index_sequence<N> {});
}

} // namespace etl

#endif // TETL_ARRAY_TO_ARRAY_HPP