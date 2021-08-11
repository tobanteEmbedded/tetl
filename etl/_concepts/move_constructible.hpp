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

#ifndef TETL_CONCEPTS_MOVE_CONSTRUCTIBLE_HPP
#define TETL_CONCEPTS_MOVE_CONSTRUCTIBLE_HPP

#include "etl/_concepts/constructible_from.hpp"
#include "etl/_concepts/convertible_to.hpp"

#if defined(__cpp_concepts)
namespace etl {

/// \brief The concept move_constructible is satisfied if T is a reference type,
/// or if it is an object type where an object of that type can be constructed
/// from an rvalue of that type in both direct- and copy-initialization
/// contexts, with the usual semantics.
/// \notes
/// [cppreference.com/w/cpp/concepts/move_constructible](https://en.cppreference.com/w/cpp/concepts/move_constructible)
template <typename T>
concept move_constructible = constructible_from<T, T> && convertible_to<T, T>;

} // namespace etl
#endif

#endif // TETL_CONCEPTS_MOVE_CONSTRUCTIBLE_HPP