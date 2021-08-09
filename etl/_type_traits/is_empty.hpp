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

#ifndef TETL_DETAIL_TYPE_TRAITS_IS_EMPTY_HPP
#define TETL_DETAIL_TYPE_TRAITS_IS_EMPTY_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/is_class.hpp"

namespace etl {

namespace detail {
template <typename T>
struct is_empty_test_struct_1 : T {
    char dummy_data;
};

struct is_empty_test_struct_2 {
    char dummy_data;
};

template <typename T, bool = ::etl::is_class<T>::value>
struct is_empty_helper
    : ::etl::bool_constant<sizeof(is_empty_test_struct_1<T>)
                           == sizeof(is_empty_test_struct_2)> {
};

template <typename T>
struct is_empty_helper<T, false> : ::etl::false_type {
};
} // namespace detail

/// \brief f T is an empty type (that is, a non-union class type with no
/// non-static data members other than bit-fields of size 0, no virtual
/// functions, no virtual base classes, and no non-empty base classes), provides
/// the member constant value equal to true. For any other type, value is false.
/// \group is_empty
template <typename T>
struct is_empty : detail::is_empty_helper<T> {
};

/// \group is_empty
template <typename T>
inline constexpr bool is_empty_v = is_empty<T>::value;

} // namespace etl

#endif // TETL_DETAIL_TYPE_TRAITS_IS_EMPTY_HPP