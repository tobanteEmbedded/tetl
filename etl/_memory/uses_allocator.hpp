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

#ifndef TETL_MEMORY_USES_ALLOCATOR_HPP
#define TETL_MEMORY_USES_ALLOCATOR_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/is_convertible.hpp"
#include "etl/_type_traits/void_t.hpp"

namespace etl {

namespace detail {
template <typename Type, typename Alloc, typename = void>
struct uses_allocator_impl : false_type {
};

template <typename Type, typename Alloc>
struct uses_allocator_impl<Type, Alloc, void_t<typename Type::allocator_type>>
    : is_convertible<Alloc, typename Type::allocator_type>::type {
};
} // namespace detail

/// \brief If T has a member typedef allocator_type which is convertible from
/// Alloc, the member constant value is true. Otherwise value is false.
template <typename Type, typename Alloc>
struct uses_allocator : detail::uses_allocator_impl<Type, Alloc>::type {
};

/// \brief If T has a member typedef allocator_type which is convertible from
/// Alloc, the member constant value is true. Otherwise value is false.
template <typename Type, typename Alloc>
inline constexpr auto uses_allocator_v = uses_allocator<Type, Alloc>::value;

} // namespace etl

#endif // TETL_MEMORY_USES_ALLOCATOR_HPP