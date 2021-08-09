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

#ifndef TETL_DETAIL_TYPE_TRAITS_IS_INTEGRAL_HPP
#define TETL_DETAIL_TYPE_TRAITS_IS_INTEGRAL_HPP

#include "etl/detail/type_traits/bool_constant.hpp"
#include "etl/detail/type_traits/remove_cv.hpp"

namespace etl {

namespace detail {

// clang-format off
template <typename> struct is_integral_impl                     : etl::false_type {};

template <>         struct is_integral_impl<bool>               : etl::true_type {};

template <>         struct is_integral_impl<char>               : etl::true_type {};
template <>         struct is_integral_impl<signed char>        : etl::true_type {};
template <>         struct is_integral_impl<unsigned char>      : etl::true_type {};

template <>         struct is_integral_impl<char16_t>           : etl::true_type {};
template <>         struct is_integral_impl<char32_t>           : etl::true_type {};

template <>         struct is_integral_impl<short>              : etl::true_type {};
template <>         struct is_integral_impl<unsigned short>     : etl::true_type {};

template <>         struct is_integral_impl<int>                : etl::true_type {};
template <>         struct is_integral_impl<unsigned int>       : etl::true_type {};

template <>         struct is_integral_impl<long>               : etl::true_type {};
template <>         struct is_integral_impl<unsigned long>      : etl::true_type {};

template <>         struct is_integral_impl<long long>          : etl::true_type {};
template <>         struct is_integral_impl<unsigned long long> : etl::true_type {};
// clang-format on

} // namespace detail

/// \group is_integral
template <typename Type>
struct is_integral : detail::is_integral_impl<remove_cv_t<Type>>::type {
};

/// \group is_integral
template <typename T>
inline constexpr bool is_integral_v = is_integral<T>::value;

} // namespace etl

#endif // TETL_DETAIL_TYPE_TRAITS_IS_INTEGRAL_HPP