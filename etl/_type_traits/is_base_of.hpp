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

#ifndef TETL_TYPE_TRAITS_IS_BASE_OF_HPP
#define TETL_TYPE_TRAITS_IS_BASE_OF_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/is_class.hpp"

namespace etl {

namespace detail {
template <typename B>
auto test_pre_ptr_convertible(B const volatile*) -> ::etl::true_type;
template <typename>
auto test_pre_ptr_convertible(void const volatile*) -> ::etl::false_type;

template <typename, typename>
auto test_pre_is_base_of(...) -> ::etl::true_type;
template <typename B, typename D>
auto test_pre_is_base_of(int)
    -> decltype(test_pre_ptr_convertible<B>(static_cast<D*>(nullptr)));
} // namespace detail

/// \brief If Derived is derived from Base or if both are the same non-union
/// class (in both cases ignoring cv-qualification), provides the member
/// constant value equal to true. Otherwise value is false.
///
/// \details If both Base and Derived are non-union class types, and they are
/// not the same type (ignoring cv-qualification), Derived shall be a complete
/// type; otherwise the behavior is undefined.
///
/// \notes
/// [cppreference.com/w/cpp/types/is_base_of](https://en.cppreference.com/w/cpp/types/is_base_of)
template <typename Base, typename Derived>
struct is_base_of
    : bool_constant<
          is_class_v<
              Base> and is_class_v<Derived>and decltype(detail::test_pre_is_base_of<Base, Derived>(0))::value> {
};

template <typename Base, typename Derived>
inline constexpr bool is_base_of_v = is_base_of<Base, Derived>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_BASE_OF_HPP