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

#ifndef TETL_DETAIL_FUNCTIONAL_IS_TRANSPARENT_HPP
#define TETL_DETAIL_FUNCTIONAL_IS_TRANSPARENT_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/conditional.hpp"
#include "etl/_type_traits/is_same.hpp"

namespace etl {

namespace detail {
template <typename T, typename, typename = void>
struct is_transparent : ::etl::false_type {
};

/// \brief is_transparent
/// \group is_transparent
/// \module Utility
template <typename T, typename U>
struct is_transparent<T, U,
    ::etl::conditional_t<::etl::is_same_v<typename T::is_transparent, void>,
        void, bool>> : ::etl::true_type {
};

/// \group is_transparent
template <typename T, typename U>
inline constexpr auto transparent_v = is_transparent<T, U>::value;

} // namespace detail

} // namespace etl

#endif // TETL_DETAIL_FUNCTIONAL_IS_TRANSPARENT_HPP