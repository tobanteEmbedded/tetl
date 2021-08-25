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

#ifndef TETL_MEMORY_POINTER_TRAITS_HPP
#define TETL_MEMORY_POINTER_TRAITS_HPP

#include "etl/_cstddef/ptrdiff_t.hpp"

namespace etl {

/// \brief The pointer_traits class template provides the standardized way to
/// access certain properties of pointer-like types.
///
/// https://en.cppreference.com/w/cpp/memory/pointer_traits
///
/// \group pointer_traits
template <typename Ptr>
struct pointer_traits {
    using pointer         = Ptr;
    using element_type    = typename Ptr::element_type;
    using difference_type = typename Ptr::difference_type;

    /// \brief Constructs a dereferenceable pointer or pointer-like object
    /// ("fancy pointer") to its argument.
    /// https://en.cppreference.com/w/cpp/memory/pointer_traits/pointer_to
    /// \param r  Reference to an object of type element_type&.
    /// \returns A pointer to r, of the type pointer_traits::pointer.
    [[nodiscard]] static auto pointer_to(element_type& r) -> pointer
    {
        return Ptr::pointer_to(r);
    }
};

/// \brief The pointer_traits class template provides the standardized way to
/// access certain properties of pointer-like types.
/// https://en.cppreference.com/w/cpp/memory/pointer_traits
/// \tparam T A raw pointer
/// \group pointer_traits
template <typename T>
struct pointer_traits<T*> {
    using pointer         = T*;
    using element_type    = T;
    using difference_type = etl::ptrdiff_t;
    template <typename U>
    using rebind = U*;

    /// \brief Constructs a dereferenceable pointer or pointer-like object
    /// ("fancy pointer") to its argument.
    /// \param r  Reference to an object of type element_type&.
    /// \returns A pointer to r, of the type pointer_traits::pointer.
    /// https://en.cppreference.com/w/cpp/memory/pointer_traits/pointer_to
    [[nodiscard]] static auto pointer_to(element_type& r) -> pointer
    {
        return addressof(r);
    }
};

} // namespace etl

#endif // TETL_MEMORY_POINTER_TRAITS_HPP