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

#ifndef TETL_DETAIL_UTILITY_IN_PLACE_TYPE_HPP
#define TETL_DETAIL_UTILITY_IN_PLACE_TYPE_HPP

#include "etl/detail/cstddef/size_t.hpp"

namespace etl {

/// \brief Disambiguation tags that can be passed to the constructors of
/// etl::optional, etl::variant, and etl::any to indicate that the contained
/// object should be constructed in-place, and (for the latter two) the type of
/// the object to be constructed.
///
/// \details The corresponding type/type templates etl::in_place_t,
/// etl::in_place_type_t and etl::in_place_index_t can be used in the
/// constructor's parameter list to match the intended tag.
template <typename T>
struct in_place_type_t {
    explicit in_place_type_t() = default;
};

template <typename T>
inline constexpr auto in_place_type = in_place_type_t<T> {};

} // namespace etl

#endif // TETL_DETAIL_UTILITY_IN_PLACE_TYPE_HPP