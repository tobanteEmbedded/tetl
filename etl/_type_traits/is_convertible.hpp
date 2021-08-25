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

#ifndef TETL_TYPE_TRAITS_IS_CONVERTIBLE_HPP
#define TETL_TYPE_TRAITS_IS_CONVERTIBLE_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/is_void.hpp"

namespace etl {

namespace detail {
template <typename>
using true_type_for = etl::true_type;

template <typename T>
auto test_returnable(int) -> true_type_for<T()>;
template <typename>
auto test_returnable(...) -> etl::false_type;

template <typename From, typename To>
auto test_nonvoid_convertible(int)
    -> true_type_for<decltype(etl::declval<void (&)(To)>()(
        etl::declval<From>()))>;
template <typename, typename>
auto test_nonvoid_convertible(...) -> etl::false_type;

} // namespace detail

/// \brief If the imaginary function definition `To test() { return
/// etl::declval<From>(); }` is well-formed, (that is, either
/// `etl::declval<From>()` can be converted to To using implicit conversions, or
/// both From and To are possibly cv-qualified void), provides the member
/// constant value equal to true. Otherwise value is false. For the purposes of
/// this check, the use of `etl::declval` in the return statement is not
/// considered an odr-use. Access checks are performed as if from a context
/// unrelated to either type. Only the validity of the immediate context of the
/// expression in the return statement (including conversions to the return
/// type) is considered.
/// \group is_convertible
template <typename From, typename To>
struct is_convertible
    : bool_constant<(decltype(detail::test_returnable<To>(
                        0))::value&& decltype(detail::
                            test_nonvoid_convertible<From, To>(0))::value)
                    || (is_void_v<From> && is_void_v<To>)> {
};

/// \group is_convertible
template <typename From, typename To>
inline constexpr bool is_convertible_v = is_convertible<From, To>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_CONVERTIBLE_HPP