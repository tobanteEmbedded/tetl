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

#ifndef TETL_DETAIL_TYPE_TRAITS_IS_UNDERLYING_TYPE_HPP
#define TETL_DETAIL_TYPE_TRAITS_IS_UNDERLYING_TYPE_HPP

#include "etl/_config/builtin_functions.hpp"
#include "etl/_type_traits/is_enum.hpp"

namespace etl {

namespace detail {
template <typename T, bool = is_enum_v<T>>
struct underlying_type_impl {
    using type = TETL_IS_UNDERLYING_TYPE(T);
};

template <typename T>
struct underlying_type_impl<T, false> {
};

} // namespace detail

/// \brief The underlying type of an enum.
template <typename T>
struct underlying_type : detail::underlying_type_impl<T> {
};

template <typename T>
using underlying_type_t = typename underlying_type<T>::type;

} // namespace etl

#endif // TETL_DETAIL_TYPE_TRAITS_IS_UNDERLYING_TYPE_HPP