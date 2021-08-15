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

#ifndef TETL_MEMORY_TO_ADDRESS_HPP
#define TETL_MEMORY_TO_ADDRESS_HPP

#include "etl/_memory/pointer_traits.hpp"
#include "etl/_type_traits/is_function.hpp"

namespace etl {

namespace detail {
template <typename T>
constexpr auto to_address_impl(T* ptr) noexcept -> T*
{
    static_assert(!is_function_v<T>);
    return ptr;
}

template <typename Ptr>
constexpr auto to_address_impl(Ptr const& ptr) noexcept
    -> decltype(pointer_traits<Ptr>::to_address(ptr))
{
    return pointer_traits<Ptr>::to_address(ptr);
}

template <typename Ptr, typename... Ignore>
constexpr auto to_address_impl(Ptr const& ptr, Ignore...) noexcept
{
    return to_address_impl(ptr.operator->());
}
} // namespace detail

/// \brief Obtain the address represented by p without forming a reference to
/// the object pointed to by p.
///
/// \details Fancy pointer overload: If the expression
/// pointer_traits<Ptr>::to_address(p) is well-formed, returns the result of
/// that expression. Otherwise, returns to_address(p.operator->()).
template <typename Ptr>
constexpr auto to_address(Ptr const& ptr) noexcept
{
    return detail::to_address_impl(ptr);
}

/// \brief Obtain the address represented by p without forming a reference to
/// the object pointed to by p.
///
/// \details Raw pointer overload: If T is a function type, the program is
/// ill-formed. Otherwise, returns p unmodified.
template <typename T>
constexpr auto to_address(T* ptr) noexcept -> T*
{
    return detail::to_address_impl(ptr);
}

} // namespace etl

#endif // TETL_MEMORY_TO_ADDRESS_HPP