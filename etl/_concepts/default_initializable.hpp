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

#ifndef TETL_CONCEPTS_DEFAULT_INITIALIZABLE_HPP
#define TETL_CONCEPTS_DEFAULT_INITIALIZABLE_HPP

#include "etl/_concepts/constructible_from.hpp"
#include "etl/_new/operator.hpp"

#if defined(__cpp_concepts)
namespace etl {

/// \brief The default_initializable concept checks whether variables of type T
/// can be value-initialized (T() is well-formed); direct-list-initialized from
/// an empty initializer list (T{} is well-formed); and default-initialized (T
/// t; is well-formed). Access checking is performed as if in a context
/// unrelated to T. Only the validity of the immediate context of the variable
/// initialization is considered.
// clang-format off
template <typename T>
concept default_initializable =
  constructible_from<T> &&
  requires { T {}; } &&
  requires { ::new (static_cast<void*>(nullptr)) T; };
// clang-format on

} // namespace etl
#endif

#endif // TETL_CONCEPTS_DEFAULT_INITIALIZABLE_HPP