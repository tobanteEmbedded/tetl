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

#ifndef TETL_ALGORITHM_SWAP_HPP
#define TETL_ALGORITHM_SWAP_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_move_assignable.hpp"
#include "etl/_type_traits/is_move_constructible.hpp"
#include "etl/_type_traits/is_nothrow_move_assignable.hpp"
#include "etl/_type_traits/is_nothrow_move_constructible.hpp"
#include "etl/_type_traits/is_swappable.hpp"
#include "etl/_type_traits/remove_reference.hpp"
#include "etl/_utility/move.hpp"

namespace etl {

/// \brief Exchanges the given values. Swaps the values a and b. This overload
/// does not participate in overload resolution unless
/// etl::is_move_constructible_v<T> && etl::is_move_assignable_v<T> is true.
///
/// \notes
/// [cppreference.com/w/cpp/algorithm/swap](https://en.cppreference.com/w/cpp/algorithm/swap)
///
/// \todo Fix noexcept specifier.
template <typename T>
constexpr auto swap(T& a, T& b) noexcept(
    is_nothrow_move_constructible_v<T>&& is_nothrow_move_assignable_v<T>)
    -> enable_if_t<is_move_constructible_v<T> && is_move_assignable_v<T>, void>
{
    T temp(move(a));
    a = move(b);
    b = move(temp);
}

template <typename T, size_t N>
constexpr auto swap(T (&a)[N], T (&b)[N]) noexcept(
    is_nothrow_swappable<T>::value) -> enable_if_t<is_swappable<T>::value, void>
{
    for (size_t i = 0; i < N; ++i) { swap(a[i], b[i]); }
}

} // namespace etl

#endif // TETL_ALGORITHM_SWAP_HPP