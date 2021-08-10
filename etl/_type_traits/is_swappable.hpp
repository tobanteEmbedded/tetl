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

#ifndef TETL_DETAIL_TYPE_TRAITS_IS_SWAPPABLE_HPP
#define TETL_DETAIL_TYPE_TRAITS_IS_SWAPPABLE_HPP

#include "etl/_algorithm/swap.hpp"
#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/is_same.hpp"

namespace etl {

namespace detail {
struct nat {
    nat()           = delete;
    nat(nat const&) = delete;
    auto operator=(nat const&) -> nat& = delete;
    ~nat()                             = delete;
};

using ::etl::swap;
template <typename T>
void swap(nat a, nat b) noexcept;

template <typename T>
struct is_swappable_helper {
    using type = decltype(swap(::etl::declval<T&>(), ::etl::declval<T&>()));
    static const bool value = !::etl::is_same_v<type, nat>;
};

} // namespace detail

/// \brief If T is not a referenceable type (i.e., possibly cv-qualified void or
/// a function type with a cv-qualifier-seq or a ref-qualifier), provides a
/// member constant value equal to false. Otherwise, provides a member constant
/// value equal to etl::is_swappable_with<T&, T&>::value
template <typename T>
struct is_swappable : bool_constant<detail::is_swappable_helper<T>::value> {
};

template <typename T>
inline constexpr bool is_swappable_v = is_swappable<T>::value;

} // namespace etl

#endif // TETL_DETAIL_TYPE_TRAITS_IS_SWAPPABLE_HPP