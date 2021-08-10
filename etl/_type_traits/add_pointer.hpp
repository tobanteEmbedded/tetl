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

#ifndef TETL_TYPE_TRAITS_ADD_POINTER_HPP
#define TETL_TYPE_TRAITS_ADD_POINTER_HPP

#include "etl/_type_traits/remove_reference.hpp"
#include "etl/_type_traits/type_identity.hpp"

namespace etl {

namespace detail {
template <typename T>
auto try_add_pointer(int) -> etl::type_identity<etl::remove_reference_t<T>*>;
template <typename T>
auto try_add_pointer(...) -> etl::type_identity<T>;

} // namespace detail

/// \brief If T is a reference type, then provides the member typedef type which
/// is a pointer to the referred type. Otherwise, if T names an object type, a
/// function type that is not cv- or ref-qualified, or a (possibly cv-qualified)
/// void type, provides the member typedef type which is the type T*. Otherwise
/// (if T is a cv- or ref-qualified function type), provides the member typedef
/// type which is the type T. The behavior of a program that adds
/// specializations for add_pointer is undefined.
/// \group add_pointer
template <typename T>
struct add_pointer : decltype(detail::try_add_pointer<T>(0)) {
};

/// \group add_pointer
template <typename T>
using add_pointer_t = typename add_pointer<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_ADD_POINTER_HPP