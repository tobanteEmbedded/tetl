

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

#ifndef TETL_UTILITY_MOVE_IF_NOEXCEPT_HPP
#define TETL_UTILITY_MOVE_IF_NOEXCEPT_HPP

#include "etl/_type_traits/conditional.hpp"
#include "etl/_type_traits/is_copy_constructible.hpp"
#include "etl/_type_traits/is_nothrow_move_constructible.hpp"
#include "etl/_utility/move.hpp"

namespace etl {

namespace detail {
template <typename T>
inline constexpr auto move_if_noexcept_cond
    = is_nothrow_move_constructible_v<T>&& is_copy_constructible_v<T>;
} // namespace detail

/// \brief  Conditionally convert a value to an rvalue.
/// \details Same as etl::move unless the type's move constructor could throw
/// and the  type is copyable, in which case an lvalue-reference is returned
/// instead.
template <typename T>
[[nodiscard]] constexpr auto move_if_noexcept(T& x) noexcept
    -> conditional_t<detail::move_if_noexcept_cond<T>, T const&, T&&>
{
    return etl::move(x);
}

} // namespace etl

#endif // TETL_UTILITY_MOVE_IF_NOEXCEPT_HPP