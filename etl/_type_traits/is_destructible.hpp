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

#ifndef TETL_DETAIL_TYPE_TRAITS_IS_DESTRUCTIBLE_HPP
#define TETL_DETAIL_TYPE_TRAITS_IS_DESTRUCTIBLE_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/disjunction.hpp"
#include "etl/_type_traits/extent.hpp"
#include "etl/_type_traits/is_function.hpp"
#include "etl/_type_traits/is_reference.hpp"
#include "etl/_type_traits/is_scalar.hpp"
#include "etl/_type_traits/is_unbounded_array.hpp"
#include "etl/_type_traits/is_void.hpp"
#include "etl/_type_traits/remove_all_extents.hpp"
#include "etl/_type_traits/type_identity.hpp"

namespace etl {

namespace detail {

struct try_is_destructible_impl {
    template <typename T, typename = decltype(::etl::declval<T&>().~T())>
    static auto test(int) -> ::etl::true_type;

    template <typename>
    static auto test(...) -> ::etl::false_type;
};

template <typename T>
struct is_destructible_impl : try_is_destructible_impl {
    using type = decltype(test<T>(0));
};

template <typename T,
    bool = ::etl::disjunction<::etl::is_void<T>, ::etl::is_function<T>,
        ::etl::is_unbounded_array<T>>::value,
    bool
    = ::etl::disjunction<::etl::is_reference<T>, ::etl::is_scalar<T>>::value>
struct is_destructible_safe;

template <typename T>
struct is_destructible_safe<T, false, false>
    : is_destructible_impl<typename ::etl::remove_all_extents_t<T>>::type {
};

template <typename T>
struct is_destructible_safe<T, true, false> : ::etl::false_type {
};

template <typename T>
struct is_destructible_safe<T, false, true> : ::etl::true_type {
};

} // namespace detail

/// \brief Because the C++ program terminates if a destructor throws an
/// exception during stack unwinding (which usually cannot be predicted), all
/// practical destructors are non-throwing even if they are not declared
/// noexcept. All destructors found in the C++ standard library are
/// non-throwing.
/// \notes
/// [cppreference.com/w/cpp/types/is_destructible](https://en.cppreference.com/w/cpp/types/is_destructible)
/// \group is_destructible
template <typename T>
struct is_destructible : detail::is_destructible_safe<T> {
};

/// \exclude
template <typename Type>
struct is_destructible<Type[]> : false_type {
};

/// \exclude
template <>
struct is_destructible<void> : false_type {
};

/// \group is_destructible
template <typename T>
inline constexpr auto is_destructible_v = is_destructible<T>::value;

} // namespace etl

#endif // TETL_DETAIL_TYPE_TRAITS_IS_DESTRUCTIBLE_HPP