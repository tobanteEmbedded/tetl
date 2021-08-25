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

#ifndef ETL_EXPERIMENTAL_META_TRAITS_ADD_HPP
#define ETL_EXPERIMENTAL_META_TRAITS_ADD_HPP

#include "etl/experimental/meta/types/type.hpp"

#include "etl/type_traits.hpp"

namespace etl::experimental::meta::traits {

#define TETL_META_DEFINE_TRAITS_ADD_FUNCTION(name)                             \
    template <typename T>                                                      \
    constexpr auto name(type<T> const& /*unused*/)                             \
        ->type<typename etl::name<T>::type>                                    \
    {                                                                          \
        return {};                                                             \
    }

TETL_META_DEFINE_TRAITS_ADD_FUNCTION(add_const)
TETL_META_DEFINE_TRAITS_ADD_FUNCTION(add_cv)
TETL_META_DEFINE_TRAITS_ADD_FUNCTION(add_lvalue_reference)
TETL_META_DEFINE_TRAITS_ADD_FUNCTION(add_pointer)
TETL_META_DEFINE_TRAITS_ADD_FUNCTION(add_rvalue_reference)
TETL_META_DEFINE_TRAITS_ADD_FUNCTION(add_volatile)

#undef TETL_META_DEFINE_TRAITS_ADD_FUNCTION

} // namespace etl::experimental::meta::traits

#endif // ETL_EXPERIMENTAL_META_TRAITS_ADD_HPP
