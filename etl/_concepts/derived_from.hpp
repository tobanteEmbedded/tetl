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

#ifndef TETL_CONCEPTS_DERIVED_FROM_HPP
#define TETL_CONCEPTS_DERIVED_FROM_HPP

#include "etl/_type_traits/is_base_of.hpp"
#include "etl/_type_traits/is_convertible.hpp"

#if defined(__cpp_concepts)
namespace etl {

/// \brief The concept derived_from<Derived, Base> is satisfied if and only if
/// Base is a class type that is either Derived or a public and unambiguous base
/// of Derived, ignoring cv-qualifiers. Note that this behaviour is different to
/// is_base_of when Base is a private or protected base of Derived.
template <typename Derived, typename Base>
concept derived_from = is_base_of_v<Base,
    Derived> && is_convertible_v<const volatile Derived*, const volatile Base*>;

} // namespace etl
#endif

#endif // TETL_CONCEPTS_DERIVED_FROM_HPP